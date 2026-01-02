# Percolator (Solana Program)

Percolator is a minimal Solana program that embeds a formally-verified-style `RiskEngine` (from the `percolator` crate) inside a single “slab” account and exposes a small instruction set for:
- market init
- user / LP account creation
- collateral deposit / withdraw
- keeper crank
- trades (no-CPI and CPI via external matcher)
- liquidation
- close account
- insurance top-up

Key design goals:
- **Single-account state**: all market state + risk engine live in one slab account (`SLAB_LEN` bytes).
- **Zero-copy engine**: `RiskEngine` is stored in-place at a fixed offset with an explicit alignment check.
- **Unsafe island**: the only `unsafe` is in the `zc` module used for zero-copy references.
- **Stable matcher ABI**: matcher returns execution results by writing a fixed prefix at the start of a context account.

---

## Accounts & Layout

### Slab account
Owned by this program. Fixed size:

- `HEADER_LEN` bytes: `SlabHeader` (magic/version/admin/bump)
- `CONFIG_LEN` bytes: `MarketConfig` (mints, vault, oracle keys, staleness/conf filters, bump)
- `RiskEngine` bytes: stored in-place at `ENGINE_OFF` (aligned to `align_of::<RiskEngine>()`)

Constants are in `constants::*`:
- `MAGIC`, `VERSION`
- `SLAB_LEN`
- `ENGINE_OFF`, `ENGINE_LEN`, `ENGINE_ALIGN`

### Vault token account
A SPL token account holding collateral. Must satisfy:
- `owner == spl_token::ID`
- mint == `MarketConfig.collateral_mint`
- owner == derived vault authority PDA:
  - `PDA = find_program_address(["vault", slab_pubkey])`

### Oracles
This code reads **Pyh v1 style price account** data directly (208-byte minimum) and converts to `price_e6` (scaled to 1e6). Enforces:
- positive price
- staleness window (`max_staleness_slots`)
- confidence constraint (`conf_filter_bps`)

---

## Instruction Set

Instruction enum lives in `ix::Instruction` and is decoded manually from bytes.

### 0. `InitMarket`
Initializes a slab and writes a fresh engine + config + header.

**Accounts (11)**
0. `admin` (signer)
1. `slab` (writable, program-owned, len == `SLAB_LEN`)
2. `collateral_mint` (readonly)
3. `vault` (readonly; must be correct SPL token account)
4. `token_program` (readonly)
5. dummy/unused (readonly) *(kept for compatibility with earlier tests)*
6. `system_program` (readonly)
7. `rent` (readonly)
8. `pyth_index` (readonly)
9. `pyth_collateral` (readonly)
10. `clock` (readonly)

### 1. `InitUser { fee_payment }`
Adds a user slot in the engine and assigns ownership to the signer.

**Accounts (7)**
0. `user` (signer)
1. `slab` (writable)
2. `user_ata` (writable)
3. `vault` (writable)
4. `token_program` (readonly)
5. `clock` (readonly)
6. `pyth_collateral` (readonly)

### 2. `InitLP { matcher_program, matcher_context, fee_payment }`
Adds an LP slot. Stores `(matcher_program, matcher_context)` in the engine.

**Accounts (7)**
0. `lp_owner` (signer)
1. `slab` (writable)
2. `lp_ata` (writable)
3. `vault` (writable)
4. `token_program` (readonly)
5. (unused in program logic; legacy in tests)
6. (unused in program logic; legacy in tests)

### 3. `DepositCollateral { user_idx, amount }`
Transfers tokens into the vault and credits engine capital.

**Accounts (5)**
0. `user` (signer)
1. `slab` (writable)
2. `user_ata` (writable)
3. `vault` (writable)
4. `token_program` (readonly)

### 4. `WithdrawCollateral { user_idx, amount }`
Runs risk checks against the index oracle and withdraws tokens from vault to user ATA.

**Accounts (8)**
0. `user` (signer)
1. `slab` (writable)
2. `vault` (writable)
3. `user_ata` (writable)
4. `vault_authority_pda` (readonly; must match derived PDA)
5. `token_program` (readonly)
6. `clock` (readonly)
7. `index_oracle` (readonly; must match config)

### 5. `KeeperCrank { caller_idx, funding_rate_bps_per_slot, allow_panic }`
Keeper updates engine funding/fees and enforces crank staleness rules.

**Accounts (4)**
0. `caller` (signer)
1. `slab` (writable)
2. `clock` (readonly)
3. `index_oracle` (readonly)

### 6. `TradeNoCpi { lp_idx, user_idx, size }`
Executes a trade using `NoOpMatcher` (used for local testing).

**Accounts (5)**
0. `user` (signer)
1. `lp_owner` (signer)
2. `slab` (writable)
3. `clock` (readonly)
4. `index_oracle` (readonly)

### 7. `LiquidateAtOracle { target_idx }`
Liquidates a position using the index oracle.

**Accounts (4)**
0. (unused)
1. `slab` (writable)
2. `clock` (readonly)
3. `index_oracle` (readonly)

### 8. `CloseAccount { user_idx }`
Closes a user account in the engine and withdraws remaining collateral.

**Accounts (8)**
0. `user` (signer)
1. `slab` (writable)
2. `vault` (writable)
3. `user_ata` (writable)
4. `vault_authority_pda` (readonly; must match)
5. `token_program` (readonly)
6. `clock` (readonly)
7. `index_oracle` (readonly)

### 9. `TopUpInsurance { amount }`
Transfers tokens into the vault and credits the engine insurance fund.

**Accounts (5)**
0. `payer` (signer)
1. `slab` (writable)
2. `payer_ata` (writable)
3. `vault` (writable)
4. `token_program` (readonly)

### 10. `TradeCpi { lp_idx, user_idx, size }`
Calls an external **matcher program** via CPI. The matcher writes the execution result into the **matcher context account** prefix. Percolator then validates the prefix and applies the trade to the engine.

**Accounts (7)**
0. `user` (signer)
1. `lp_owner` (signer)
2. `slab` (writable)
3. `clock` (readonly)
4. `index_oracle` (readonly; must match config)
5. `matcher_program` (executable)
6. `matcher_context` (writable; owned by matcher_program; `data_len >= MATCHER_CONTEXT_LEN`)

The LP PDA is **not passed as an account**. It is synthesized as a pure signer via `invoke_signed` seeds:
- `PDA = find_program_address(["lp", slab_pubkey, lp_idx_le], percolator_program_id)`

---

## Matcher ABI (Stable)

The matcher returns execution data by writing the first 64 bytes of the context account.

`MatcherReturn` layout (little-endian, total 64 bytes):
- `u32 abi_version`
- `u32 flags` (bit0 = valid; bit2 = rejected)
- `u64 exec_price_e6`
- `i128 exec_size`
- `u64 req_id`
- `u64 lp_account_id`
- `u64 oracle_price_e6`
- `u64 reserved` (must be 0)

Percolator validates:
- `abi_version == MATCHER_ABI_VERSION`
- `flags` indicates valid and not rejected
- `exec_price_e6 != 0`
- `lp_account_id` matches the engine LP account id
- `oracle_price_e6` matches the oracle used in this instruction
- `reserved == 0`
- `exec_size` is bounded and direction-consistent with requested `size`

---

## Building & Testing

### Unit tests
```bash
cargo test