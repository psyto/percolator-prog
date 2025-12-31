use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use percolator::{RiskEngine, RiskParams, NoOpMatcher};

fn default_params() -> RiskParams {
    RiskParams {
        warmup_period_slots: 10,
        maintenance_margin_bps: 500,
        initial_margin_bps: 1000,
        trading_fee_bps: 10,
        max_accounts: 64,
        new_account_fee: 0,
        risk_reduction_threshold: 0,
        maintenance_fee_per_slot: 0,
        max_crank_staleness_slots: 100,
        liquidation_fee_bps: 50,
        liquidation_fee_cap: 1000,
        liquidation_buffer_bps: 100,
        min_liquidation_abs: 10,
    }
}

#[test]
fn deterministic_fuzz_simulation() {
    let seed = [0xabu8; 16];
    let mut rng = XorShiftRng::from_seed(seed);
    let mut engine = RiskEngine::new(default_params());

    let mut users = Vec::new();
    let mut lps = Vec::new();

    for i in 0..500 {
        let op: u8 = rng.gen_range(0..6);
        let slot = (i / 10) as u64; // Advance slot slowly
        let price = (100_000_000 + rng.gen_range(0..20_000_000)) - 10_000_000; // 100 +/- 10

        match op {
            0 => { // Add User
                if let Ok(idx) = engine.add_user(0) {
                    users.push(idx);
                }
            },
            1 => { // Add LP
                if let Ok(idx) = engine.add_lp([0; 32], [0; 32], 0) {
                    lps.push(idx);
                }
            },
            2 => { // Deposit
                if !users.is_empty() {
                    let u = users[rng.gen_range(0..users.len())];
                    let amt = rng.gen_range(1000..1_000_000);
                    let _ = engine.deposit(u, amt);
                }
            },
            3 => { // Trade
                if !users.is_empty() && !lps.is_empty() {
                    let u = users[rng.gen_range(0..users.len())];
                    let l = lps[rng.gen_range(0..lps.len())];
                    let size = rng.gen_range(-10000..10000);
                    let _ = engine.execute_trade(&NoOpMatcher, l, u, slot, price, size);
                }
            },
            4 => { // Crank
                if !users.is_empty() {
                    let u = users[rng.gen_range(0..users.len())];
                    let _ = engine.keeper_crank(u, slot, price, 0, false);
                }
            },
            5 => { // Withdraw
                if !users.is_empty() {
                    let u = users[rng.gen_range(0..users.len())];
                    let amt = rng.gen_range(1..10000);
                    let _ = engine.withdraw(u, amt, slot, price);
                }
            },
            _ => {}
        }

        assert!(engine.check_conservation(), "Conservation violated at step {}", i);
    }
}