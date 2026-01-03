//! Kani formal verification harnesses for percolator-prog.
//!
//! Run with: `cargo kani --tests`
//!
//! These harnesses prove PROGRAM-LEVEL security properties:
//! - Matcher ABI validation rejects malformed/malicious returns
//! - Owner/signer enforcement for all account operations
//! - Admin authorization and burned admin handling
//! - CPI identity binding (matcher program/context match LP registration)
//! - Matcher account shape validation
//! - PDA key mismatch rejection
//! - Nonce monotonicity (unchanged on failure, +1 on success)
//! - CPI uses exec_size (not requested size)
//!
//! Note: CPI execution and risk engine internals are NOT modeled.
//! Only wrapper-level authorization and binding logic is proven.

#![cfg(kani)]

// Import real types and helpers from the program crate
use percolator_prog::matcher_abi::{
    MatcherReturn, validate_matcher_return, FLAG_VALID, FLAG_PARTIAL_OK, FLAG_REJECTED,
};
use percolator_prog::constants::MATCHER_ABI_VERSION;
use percolator_prog::verify::{
    owner_ok, admin_ok, matcher_identity_ok, matcher_shape_ok, MatcherAccountsShape,
    gate_active, nonce_on_success, nonce_on_failure, pda_key_matches, cpi_trade_size,
    crank_authorized,
};

// =============================================================================
// Test Fixtures
// =============================================================================

/// Create a MatcherReturn from individual symbolic fields
fn any_matcher_return() -> MatcherReturn {
    MatcherReturn {
        abi_version: kani::any(),
        flags: kani::any(),
        exec_price_e6: kani::any(),
        exec_size: kani::any(),
        req_id: kani::any(),
        lp_account_id: kani::any(),
        oracle_price_e6: kani::any(),
        reserved: kani::any(),
    }
}

// =============================================================================
// A. MATCHER ABI VALIDATION (11 proofs - program-level, keep these)
// =============================================================================

/// Prove: wrong ABI version is always rejected
#[kani::proof]
fn kani_matcher_rejects_wrong_abi_version() {
    let mut ret = any_matcher_return();
    kani::assume(ret.abi_version != MATCHER_ABI_VERSION);

    let lp_account_id: u64 = kani::any();
    let oracle_price: u64 = kani::any();
    let req_size: i128 = kani::any();
    let req_id: u64 = kani::any();

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "wrong ABI version must be rejected");
}

/// Prove: missing VALID flag is always rejected
#[kani::proof]
fn kani_matcher_rejects_missing_valid_flag() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    kani::assume((ret.flags & FLAG_VALID) == 0);

    let lp_account_id: u64 = kani::any();
    let oracle_price: u64 = kani::any();
    let req_size: i128 = kani::any();
    let req_id: u64 = kani::any();

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "missing VALID flag must be rejected");
}

/// Prove: REJECTED flag always causes rejection
#[kani::proof]
fn kani_matcher_rejects_rejected_flag() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags |= FLAG_VALID;
    ret.flags |= FLAG_REJECTED;

    let lp_account_id: u64 = kani::any();
    let oracle_price: u64 = kani::any();
    let req_size: i128 = kani::any();
    let req_id: u64 = kani::any();

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "REJECTED flag must cause rejection");
}

/// Prove: wrong req_id is always rejected
#[kani::proof]
fn kani_matcher_rejects_wrong_req_id() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    let req_size: i128 = kani::any();
    kani::assume(req_size != 0);
    kani::assume(req_size != i128::MIN);
    kani::assume(ret.exec_size != 0);
    kani::assume(ret.exec_size != i128::MIN);
    kani::assume(ret.exec_size.signum() == req_size.signum());
    kani::assume(ret.exec_size.abs() <= req_size.abs());

    let req_id: u64 = kani::any();
    kani::assume(ret.req_id != req_id);

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "wrong req_id must be rejected");
}

/// Prove: wrong lp_account_id is always rejected
#[kani::proof]
fn kani_matcher_rejects_wrong_lp_account_id() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);

    let lp_account_id: u64 = kani::any();
    kani::assume(ret.lp_account_id != lp_account_id);

    let oracle_price: u64 = ret.oracle_price_e6;
    let req_size: i128 = kani::any();
    let req_id: u64 = ret.req_id;

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "wrong lp_account_id must be rejected");
}

/// Prove: wrong oracle_price is always rejected
#[kani::proof]
fn kani_matcher_rejects_wrong_oracle_price() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = kani::any();
    kani::assume(ret.oracle_price_e6 != oracle_price);

    let req_size: i128 = kani::any();
    let req_id: u64 = ret.req_id;

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "wrong oracle_price must be rejected");
}

/// Prove: non-zero reserved field is always rejected
#[kani::proof]
fn kani_matcher_rejects_nonzero_reserved() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    kani::assume(ret.exec_price_e6 != 0);
    kani::assume(ret.reserved != 0);

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    let req_size: i128 = kani::any();
    let req_id: u64 = ret.req_id;

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "non-zero reserved must be rejected");
}

/// Prove: zero exec_price is always rejected
#[kani::proof]
fn kani_matcher_rejects_zero_exec_price() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    ret.reserved = 0;
    ret.exec_price_e6 = 0;

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    let req_size: i128 = kani::any();
    let req_id: u64 = ret.req_id;

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "zero exec_price must be rejected");
}

/// Prove: zero exec_size without PARTIAL_OK is rejected
#[kani::proof]
fn kani_matcher_zero_size_requires_partial_ok() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID; // No PARTIAL_OK
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);
    ret.exec_size = 0;

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    let req_size: i128 = kani::any();
    let req_id: u64 = ret.req_id;

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "zero exec_size without PARTIAL_OK must be rejected");
}

/// Prove: exec_size exceeding req_size is rejected
#[kani::proof]
fn kani_matcher_rejects_exec_size_exceeds_req() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);
    kani::assume(ret.exec_size != 0);
    kani::assume(ret.exec_size != i128::MIN);

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    let req_id: u64 = ret.req_id;

    let req_size: i128 = kani::any();
    kani::assume(req_size != i128::MIN);
    kani::assume(ret.exec_size.abs() > req_size.abs());

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "exec_size exceeding req_size must be rejected");
}

/// Prove: sign mismatch between exec_size and req_size is rejected
#[kani::proof]
fn kani_matcher_rejects_sign_mismatch() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);
    kani::assume(ret.exec_size != 0);
    kani::assume(ret.exec_size != i128::MIN);

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    let req_id: u64 = ret.req_id;

    let req_size: i128 = kani::any();
    kani::assume(req_size != 0);
    kani::assume(req_size != i128::MIN);
    kani::assume(ret.exec_size.signum() != req_size.signum());
    kani::assume(ret.exec_size.abs() <= req_size.abs());

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "sign mismatch must be rejected");
}

// =============================================================================
// B. OWNER/SIGNER ENFORCEMENT (2 proofs)
// =============================================================================

/// Prove: owner mismatch is rejected
#[kani::proof]
fn kani_owner_mismatch_rejected() {
    let stored: [u8; 32] = kani::any();
    let signer: [u8; 32] = kani::any();
    kani::assume(stored != signer);

    assert!(
        !owner_ok(stored, signer),
        "owner mismatch must be rejected"
    );
}

/// Prove: owner match is accepted
#[kani::proof]
fn kani_owner_match_accepted() {
    let owner: [u8; 32] = kani::any();

    assert!(
        owner_ok(owner, owner),
        "owner match must be accepted"
    );
}

// =============================================================================
// C. ADMIN AUTHORIZATION (3 proofs)
// =============================================================================

/// Prove: admin mismatch is rejected
#[kani::proof]
fn kani_admin_mismatch_rejected() {
    let admin: [u8; 32] = kani::any();
    let signer: [u8; 32] = kani::any();
    kani::assume(admin != [0u8; 32]); // Not burned
    kani::assume(admin != signer);

    assert!(
        !admin_ok(admin, signer),
        "admin mismatch must be rejected"
    );
}

/// Prove: admin match is accepted (when not burned)
#[kani::proof]
fn kani_admin_match_accepted() {
    let admin: [u8; 32] = kani::any();
    kani::assume(admin != [0u8; 32]); // Not burned

    assert!(
        admin_ok(admin, admin),
        "admin match must be accepted"
    );
}

/// Prove: burned admin (all zeros) disables all admin ops
#[kani::proof]
fn kani_admin_burned_disables_ops() {
    let burned_admin = [0u8; 32];
    let signer: [u8; 32] = kani::any();

    assert!(
        !admin_ok(burned_admin, signer),
        "burned admin must disable all admin ops"
    );
}

// =============================================================================
// D. CPI IDENTITY BINDING (2 proofs) - CRITICAL
// =============================================================================

/// Prove: CPI matcher identity mismatch (program or context) is rejected
#[kani::proof]
fn kani_matcher_identity_mismatch_rejected() {
    let lp_prog: [u8; 32] = kani::any();
    let lp_ctx: [u8; 32] = kani::any();
    let provided_prog: [u8; 32] = kani::any();
    let provided_ctx: [u8; 32] = kani::any();

    // At least one must mismatch
    kani::assume(lp_prog != provided_prog || lp_ctx != provided_ctx);

    assert!(
        !matcher_identity_ok(lp_prog, lp_ctx, provided_prog, provided_ctx),
        "matcher identity mismatch must be rejected"
    );
}

/// Prove: CPI matcher identity match is accepted
#[kani::proof]
fn kani_matcher_identity_match_accepted() {
    let prog: [u8; 32] = kani::any();
    let ctx: [u8; 32] = kani::any();

    assert!(
        matcher_identity_ok(prog, ctx, prog, ctx),
        "matcher identity match must be accepted"
    );
}

// =============================================================================
// E. MATCHER ACCOUNT SHAPE VALIDATION (5 proofs)
// =============================================================================

/// Prove: non-executable matcher program is rejected
#[kani::proof]
fn kani_matcher_shape_rejects_non_executable_prog() {
    let shape = MatcherAccountsShape {
        prog_executable: false, // BAD
        ctx_executable: false,
        ctx_owner_is_prog: true,
        ctx_len_ok: true,
    };

    assert!(
        !matcher_shape_ok(shape),
        "non-executable matcher program must be rejected"
    );
}

/// Prove: executable matcher context is rejected
#[kani::proof]
fn kani_matcher_shape_rejects_executable_ctx() {
    let shape = MatcherAccountsShape {
        prog_executable: true,
        ctx_executable: true, // BAD
        ctx_owner_is_prog: true,
        ctx_len_ok: true,
    };

    assert!(
        !matcher_shape_ok(shape),
        "executable matcher context must be rejected"
    );
}

/// Prove: context not owned by program is rejected
#[kani::proof]
fn kani_matcher_shape_rejects_wrong_ctx_owner() {
    let shape = MatcherAccountsShape {
        prog_executable: true,
        ctx_executable: false,
        ctx_owner_is_prog: false, // BAD
        ctx_len_ok: true,
    };

    assert!(
        !matcher_shape_ok(shape),
        "context not owned by program must be rejected"
    );
}

/// Prove: insufficient context length is rejected
#[kani::proof]
fn kani_matcher_shape_rejects_short_ctx() {
    let shape = MatcherAccountsShape {
        prog_executable: true,
        ctx_executable: false,
        ctx_owner_is_prog: true,
        ctx_len_ok: false, // BAD
    };

    assert!(
        !matcher_shape_ok(shape),
        "insufficient context length must be rejected"
    );
}

/// Prove: valid matcher shape is accepted
#[kani::proof]
fn kani_matcher_shape_valid_accepted() {
    let shape = MatcherAccountsShape {
        prog_executable: true,
        ctx_executable: false,
        ctx_owner_is_prog: true,
        ctx_len_ok: true,
    };

    assert!(
        matcher_shape_ok(shape),
        "valid matcher shape must be accepted"
    );
}

// =============================================================================
// F. PDA KEY MATCHING (2 proofs)
// =============================================================================

/// Prove: PDA key mismatch is rejected
#[kani::proof]
fn kani_pda_mismatch_rejected() {
    let expected: [u8; 32] = kani::any();
    let provided: [u8; 32] = kani::any();
    kani::assume(expected != provided);

    assert!(
        !pda_key_matches(expected, provided),
        "PDA key mismatch must be rejected"
    );
}

/// Prove: PDA key match is accepted
#[kani::proof]
fn kani_pda_match_accepted() {
    let key: [u8; 32] = kani::any();

    assert!(
        pda_key_matches(key, key),
        "PDA key match must be accepted"
    );
}

// =============================================================================
// G. NONCE MONOTONICITY (3 proofs)
// =============================================================================

/// Prove: nonce unchanged on failure
#[kani::proof]
fn kani_nonce_unchanged_on_failure() {
    let old_nonce: u64 = kani::any();
    let new_nonce = nonce_on_failure(old_nonce);

    assert_eq!(
        new_nonce, old_nonce,
        "nonce must be unchanged on failure"
    );
}

/// Prove: nonce advances by exactly 1 on success
#[kani::proof]
fn kani_nonce_advances_on_success() {
    let old_nonce: u64 = kani::any();
    let new_nonce = nonce_on_success(old_nonce);

    assert_eq!(
        new_nonce,
        old_nonce.wrapping_add(1),
        "nonce must advance by 1 on success"
    );
}

/// Prove: nonce wraps correctly at u64::MAX
#[kani::proof]
fn kani_nonce_wraps_at_max() {
    let old_nonce = u64::MAX;
    let new_nonce = nonce_on_success(old_nonce);

    assert_eq!(
        new_nonce, 0,
        "nonce must wrap to 0 at u64::MAX"
    );
}

// =============================================================================
// H. CPI USES EXEC_SIZE (1 proof) - CRITICAL
// =============================================================================

/// Prove: CPI path uses exec_size from matcher, not requested size
#[kani::proof]
fn kani_cpi_uses_exec_size() {
    let exec_size: i128 = kani::any();
    let requested_size: i128 = kani::any();

    // Even when they differ, cpi_trade_size returns exec_size
    let chosen = cpi_trade_size(exec_size, requested_size);

    assert_eq!(
        chosen, exec_size,
        "CPI must use exec_size, not requested size"
    );
}

// =============================================================================
// I. GATE ACTIVATION LOGIC (3 proofs)
// =============================================================================

/// Prove: gate not active when threshold is zero
#[kani::proof]
fn kani_gate_inactive_when_threshold_zero() {
    let balance: u128 = kani::any();

    assert!(
        !gate_active(0, balance),
        "gate must be inactive when threshold is zero"
    );
}

/// Prove: gate not active when balance exceeds threshold
#[kani::proof]
fn kani_gate_inactive_when_balance_exceeds() {
    let threshold: u128 = kani::any();
    let balance: u128 = kani::any();
    kani::assume(balance > threshold);

    assert!(
        !gate_active(threshold, balance),
        "gate must be inactive when balance > threshold"
    );
}

/// Prove: gate active when threshold > 0 and balance <= threshold
#[kani::proof]
fn kani_gate_active_when_conditions_met() {
    let threshold: u128 = kani::any();
    kani::assume(threshold > 0);
    let balance: u128 = kani::any();
    kani::assume(balance <= threshold);

    assert!(
        gate_active(threshold, balance),
        "gate must be active when threshold > 0 and balance <= threshold"
    );
}

// =============================================================================
// J. KEEPER CRANK AUTHORIZATION (3 proofs)
// =============================================================================

/// Prove: crank authorized when account doesn't exist
#[kani::proof]
fn kani_crank_authorized_no_account() {
    let signer: [u8; 32] = kani::any();
    let stored_owner: [u8; 32] = kani::any();

    assert!(
        crank_authorized(false, stored_owner, signer),
        "crank must be authorized when account doesn't exist"
    );
}

/// Prove: crank authorized when signer matches owner
#[kani::proof]
fn kani_crank_authorized_owner_match() {
    let owner: [u8; 32] = kani::any();

    assert!(
        crank_authorized(true, owner, owner),
        "crank must be authorized when signer matches owner"
    );
}

/// Prove: crank rejected when signer doesn't match owner
#[kani::proof]
fn kani_crank_rejected_owner_mismatch() {
    let stored_owner: [u8; 32] = kani::any();
    let signer: [u8; 32] = kani::any();
    kani::assume(stored_owner != signer);

    assert!(
        !crank_authorized(true, stored_owner, signer),
        "crank must be rejected when signer doesn't match existing account owner"
    );
}
