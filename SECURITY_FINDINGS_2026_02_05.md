# Security Deep Dive Findings - 2026-02-05

## Methodology

S-tier Trail of Bits-style security review focusing on:
- Complex code paths in execute_trade, withdraw, keeper_crank
- Aggregate consistency (c_tot, pnl_pos_tot, LP aggregates)
- Haircut ratio manipulation vectors
- Integer overflow/underflow edge cases
- Position flip and margin calculation logic
- Cross-slot timing attacks
- Force-close aggregate handling

## Findings Summary

| # | Severity | Title | Status |
|---|----------|-------|--------|
| 1 | LOW | Force-close doesn't update OI/LP aggregates | DOCUMENTED |
| 2 | INFO | entry_price = 0 initialization (code smell) | DOCUMENTED |
| 3 | INFO | reserved_pnl is unused (dead code) | DOCUMENTED |
| 4 | N/A | Haircut TOCTOU | NOT EXPLOITABLE |
| 5 | N/A | LP aggregate desync in partial close | VERIFIED CORRECT |

---

## Finding #1: Force-Close Doesn't Update OI/LP Aggregates

**Severity**: LOW
**Location**: `percolator-prog/src/percolator.rs` lines 2713-2740

### Description

The force-close code in resolved market cranks directly zeroes positions without updating:
- `total_open_interest`
- `net_lp_pos`, `lp_sum_abs`, `lp_max_abs` (for LP accounts)

```rust
// Lines 2732-2734 - missing aggregate updates:
engine.accounts[idx as usize].position_size = percolator::I128::ZERO;
engine.accounts[idx as usize].entry_price = 0;
// No total_open_interest -= abs(pos)
// No LP aggregate updates
```

Compare to `oracle_close_position_core` (engine library) lines 1910-1917:
```rust
// Update OI
self.total_open_interest = self.total_open_interest - abs_pos;

// Update LP aggregates if LP
if self.accounts[idx as usize].is_lp() {
    self.net_lp_pos = self.net_lp_pos - pos;
    self.lp_sum_abs = self.lp_sum_abs - abs_pos;
}
```

### Impact Assessment

**LOW** because:
1. Trading is blocked in resolved markets (is_resolved guard)
2. Funding rate calculations using net_lp_pos become irrelevant
3. Risk threshold using LP aggregates is irrelevant post-resolution
4. total_open_interest is primarily informational

### Recommendation

Consider adding aggregate updates for consistency:
```rust
// Update total_open_interest
let abs_pos = pos.unsigned_abs();
engine.total_open_interest = engine.total_open_interest - abs_pos;

// Update LP aggregates if LP
if engine.accounts[idx as usize].is_lp() {
    engine.net_lp_pos = engine.net_lp_pos - pos;
    engine.lp_sum_abs = engine.lp_sum_abs - abs_pos;
}
```

---

## Finding #2: entry_price = 0 Initialization (Code Smell)

**Severity**: INFO
**Location**: `percolator/src/percolator.rs` lines 930, 990

### Description

User and LP accounts are initialized with `entry_price: 0`. While not currently exploitable, this is a code smell because:

1. `mark_pnl_for_position()` doesn't check for entry_price = 0
2. If a new settlement path were added that doesn't first call `settle_mark_to_oracle()`, mark PnL would be computed against entry = 0

### Current Mitigation

`execute_trade()` always calls `settle_mark_to_oracle()` (lines 2790-2791) before position changes, which sets `entry_price = oracle_price`. This ensures no exploitable window exists.

### Recommendation

Add defensive assertion in `mark_pnl_for_position`:
```rust
debug_assert!(entry > 0, "mark_pnl called with uninitialized entry_price");
```

---

## Finding #3: reserved_pnl is Unused (Dead Code)

**Severity**: INFO
**Location**: `percolator/src/percolator.rs` line 119

### Description

The `reserved_pnl` field in Account is:
- Initialized to 0 in `empty_account()`
- Read in multiple places (warmup, GC, etc.)
- **Never set to non-zero value** anywhere in the codebase

This appears to be placeholder code for future functionality (pending withdrawal reservations) that was never implemented.

### Impact

None - dead code that's correctly handled (always 0, subtracted from PnL, no effect).

### Recommendation

Either:
1. Remove the field and simplify calculations
2. Document as reserved for future use

---

## Verified Secure (Not Exploitable)

### Haircut Ratio TOCTOU

**Hypothesis**: Can haircut ratio be manipulated between computation and use?

**Analysis**: In `execute_trade()`:
1. Haircut computed at lines 2892-2906 with projected_pnl_pos_tot
2. State committed at lines 3003-3036

**Verdict**: NOT EXPLOITABLE because:
- Solana is single-threaded - no concurrent transaction interleaving
- Projected haircut correctly accounts for post-trade PnL
- Fee movement (C→I) doesn't change Residual = V - C_tot - I

### LP Aggregate Updates in Partial Close

**Hypothesis**: Are net_lp_pos, lp_sum_abs updated correctly in partial liquidation?

**Analysis**: `oracle_close_position_slice_core()` at lines 1850-1854:
```rust
if self.accounts[idx as usize].is_lp() {
    let new_pos = self.accounts[idx as usize].position_size.get();  // Reads AFTER assignment
    self.net_lp_pos = self.net_lp_pos - pos + new_pos;
    self.lp_sum_abs = self.lp_sum_abs - close_abs;
}
```

**Verdict**: CORRECT - `position_size` is modified at line 1840, then read at line 1851.

### Position Flip Detection

**Hypothesis**: Can initial margin be bypassed on position flips?

**Analysis**: Lines 2948-2955 in execute_trade:
```rust
let user_crosses_zero =
    (old_user_pos > 0 && new_user_position < 0) || (old_user_pos < 0 && new_user_position > 0);
let user_risk_increasing = new_user_pos_abs > old_user_pos_abs || user_crosses_zero;
let margin_bps = if user_risk_increasing {
    self.params.initial_margin_bps
} else {
    self.params.maintenance_margin_bps
};
```

**Verdict**: CORRECT - Flips require initial margin as intended.

### Two-Pass Settlement (Finding G Fix)

**Hypothesis**: Can profit conversion use stale haircut?

**Analysis**: Lines 3072-3076:
```rust
self.settle_loss_only(user_idx)?;  // Increases Residual
self.settle_loss_only(lp_idx)?;    // Increases Residual
self.settle_warmup_to_capital(user_idx)?;  // Uses updated haircut
self.settle_warmup_to_capital(lp_idx)?;    // Uses updated haircut
```

**Verdict**: CORRECT - Losses settled first increase Residual, then profit conversion uses fresh haircut.

### Bug #9 Fix (Hyperp Index Smoothing)

**Analysis**: Lines 1976-1980:
```rust
if cap_e2bps == 0 || dt_slots == 0 { return index; }  // Returns index, not mark
```

**Verdict**: FIXED - When dt=0 (same slot), index is returned unchanged preventing rate limit bypass.

---

## Attack Vectors Tested

| Category | Vectors Tested | Result |
|----------|---------------|--------|
| MEV | Frontrunning resolution, sandwich attacks | MITIGATED (trading blocked) |
| Oracle | Stale price, price manipulation | MITIGATED (circuit breaker) |
| Haircut | Ratio manipulation, TOCTOU | NOT EXPLOITABLE |
| Aggregates | c_tot, pnl_pos_tot desync | PROVEN SAFE (Kani) |
| Margin | Flip bypass, maintenance vs initial | CORRECT |
| Warmup | Bypass profit warmup | NOT EXPLOITABLE |
| Funding | Retroactive rate changes | MITIGATED (anti-retroactivity) |
| Force-close | Aggregate desync | LOW (non-critical post-resolution) |

---

## Conclusion

**Production Ready**: The codebase demonstrates strong security properties with:
- 279 Kani proofs including aggregate consistency
- Comprehensive margin enforcement
- Anti-manipulation guards (warmup, funding, circuit breaker)
- Correct two-pass settlement for haircut accuracy

**Remaining Low-Severity Items**:
1. Force-close aggregate updates (cosmetic in resolved context)
2. entry_price=0 code smell (defensive hardening)
3. reserved_pnl dead code (cleanup)

No exploitable vulnerabilities found in this deep dive.
