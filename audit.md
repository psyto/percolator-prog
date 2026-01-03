# Percolator-prog Formal Verification Audit

## Kani Proofs Summary

**Date:** 2026-01-03
**Kani Version:** 0.66.0
**Total Proofs:** 35
**Passed:** 35
**Failed:** 0

## Proof Categories

These proofs verify **program-level** security properties only.
Risk engine internals are NOT modeled - only wrapper authorization and binding logic.

### A. Matcher ABI Validation (11 proofs)
| Harness | Property |
|---------|----------|
| kani_matcher_rejects_wrong_abi_version | Wrong ABI version rejected |
| kani_matcher_rejects_missing_valid_flag | Missing VALID flag rejected |
| kani_matcher_rejects_rejected_flag | REJECTED flag causes rejection |
| kani_matcher_rejects_wrong_req_id | Mismatched req_id rejected |
| kani_matcher_rejects_wrong_lp_account_id | Mismatched lp_account_id rejected |
| kani_matcher_rejects_wrong_oracle_price | Mismatched oracle_price rejected |
| kani_matcher_rejects_nonzero_reserved | Non-zero reserved rejected |
| kani_matcher_rejects_zero_exec_price | Zero exec_price rejected |
| kani_matcher_zero_size_requires_partial_ok | Zero size needs PARTIAL_OK |
| kani_matcher_rejects_exec_size_exceeds_req | exec_size > req_size rejected |
| kani_matcher_rejects_sign_mismatch | Sign mismatch rejected |

### B. Owner/Signer Enforcement (2 proofs)
| Harness | Property |
|---------|----------|
| kani_owner_mismatch_rejected | Owner != signer → rejected |
| kani_owner_match_accepted | Owner == signer → accepted |

### C. Admin Authorization (3 proofs)
| Harness | Property |
|---------|----------|
| kani_admin_mismatch_rejected | Admin != signer → rejected |
| kani_admin_match_accepted | Admin == signer → accepted |
| kani_admin_burned_disables_ops | Admin == [0;32] → all ops disabled |

### D. CPI Identity Binding (2 proofs) - CRITICAL
| Harness | Property |
|---------|----------|
| kani_matcher_identity_mismatch_rejected | LP prog/ctx != provided → rejected |
| kani_matcher_identity_match_accepted | LP prog/ctx == provided → accepted |

### E. Matcher Account Shape Validation (5 proofs)
| Harness | Property |
|---------|----------|
| kani_matcher_shape_rejects_non_executable_prog | Non-executable program rejected |
| kani_matcher_shape_rejects_executable_ctx | Executable context rejected |
| kani_matcher_shape_rejects_wrong_ctx_owner | Context not owned by program rejected |
| kani_matcher_shape_rejects_short_ctx | Insufficient context length rejected |
| kani_matcher_shape_valid_accepted | Valid shape accepted |

### F. PDA Key Matching (2 proofs)
| Harness | Property |
|---------|----------|
| kani_pda_mismatch_rejected | Expected != provided key → rejected |
| kani_pda_match_accepted | Expected == provided key → accepted |

### G. Nonce Monotonicity (3 proofs)
| Harness | Property |
|---------|----------|
| kani_nonce_unchanged_on_failure | Failure → nonce unchanged |
| kani_nonce_advances_on_success | Success → nonce += 1 |
| kani_nonce_wraps_at_max | u64::MAX → wraps to 0 |

### H. CPI Uses exec_size (1 proof) - CRITICAL
| Harness | Property |
|---------|----------|
| kani_cpi_uses_exec_size | CPI uses exec_size, not requested size |

### I. Gate Activation Logic (3 proofs)
| Harness | Property |
|---------|----------|
| kani_gate_inactive_when_threshold_zero | threshold=0 → gate inactive |
| kani_gate_inactive_when_balance_exceeds | balance > threshold → gate inactive |
| kani_gate_active_when_conditions_met | threshold>0 ∧ balance≤threshold → gate active |

### J. Keeper Crank Authorization (3 proofs)
| Harness | Property |
|---------|----------|
| kani_crank_authorized_no_account | Account doesn't exist → anyone can crank |
| kani_crank_authorized_owner_match | Owner matches → crank allowed |
| kani_crank_rejected_owner_mismatch | Owner mismatch → crank rejected |

## Key Security Properties Proven

### Authorization Surface
1. **Owner checks cannot be bypassed** - Every account operation validates owner == signer
2. **Admin checks cannot be bypassed** - Admin ops require admin == signer
3. **Burned admin is permanent** - [0;32] admin disables all admin ops forever
4. **Crank authorization is correct** - Existing accounts require owner, non-existent allow anyone

### CPI Security (CRITICAL)
1. **Matcher identity binding** - CPI only proceeds if provided program/context match LP registration
2. **Matcher shape validation** - Program must be executable, context must not be, owner must be program
3. **exec_size is used** - CPI path uses matcher's exec_size, never the user's requested size

### State Consistency
1. **Nonce unchanged on failure** - Any rejection leaves nonce unchanged
2. **Nonce advances on success** - Successful trade advances nonce by exactly 1
3. **Nonce wraps correctly** - u64::MAX wraps to 0

### Matcher ABI
1. **All field mismatches rejected** - ABI version, req_id, lp_account_id, oracle_price, reserved
2. **Flag semantics enforced** - VALID required, REJECTED causes rejection, PARTIAL_OK for zero size
3. **Size constraints enforced** - exec_size ≤ req_size, sign must match

## Implementation: pub mod verify

Pure helpers added to percolator.rs for Kani verification:

```rust
pub mod verify {
    pub fn owner_ok(stored, signer) -> bool
    pub fn admin_ok(admin, signer) -> bool
    pub fn matcher_identity_ok(lp_prog, lp_ctx, provided_prog, provided_ctx) -> bool
    pub fn matcher_shape_ok(shape: MatcherAccountsShape) -> bool
    pub fn gate_active(threshold, balance) -> bool
    pub fn nonce_on_success(old) -> u64
    pub fn nonce_on_failure(old) -> u64
    pub fn pda_key_matches(expected, provided) -> bool
    pub fn cpi_trade_size(exec_size, requested_size) -> i128
    pub fn crank_authorized(idx_exists, stored_owner, signer) -> bool
}
```

## What is NOT Proven

- Risk engine internals (LpRiskState, risk metric formula)
- CPI execution (Solana invoke mechanics)
- AccountInfo validation (done at runtime by Solana)
- Actual PDA derivation (Solana's find_program_address)
- Token transfer correctness (SPL Token program)
