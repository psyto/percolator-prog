#[cfg(kani)]
mod verification {
    use super::*;
    use percolator::{RiskEngine, RiskParams};

    #[kani::proof]
    fn verify_engine_init() {
        let params = RiskParams {
            warmup_period_slots: kani::any(),
            maintenance_margin_bps: kani::any(),
            initial_margin_bps: kani::any(),
            trading_fee_bps: kani::any(),
            max_accounts: 8, // Force small
            new_account_fee: kani::any(),
            risk_reduction_threshold: kani::any(),
            maintenance_fee_per_slot: kani::any(),
            max_crank_staleness_slots: kani::any(),
            liquidation_fee_bps: kani::any(),
            liquidation_fee_cap: kani::any(),
            liquidation_buffer_bps: kani::any(),
            min_liquidation_abs: kani::any(),
        };

        let engine = RiskEngine::new(params);
        assert!(engine.check_conservation());
    }
}