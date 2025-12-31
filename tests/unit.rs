#[cfg(test)]
mod tests {
    use percolator::{RiskEngine, RiskParams, AccountKind};
    use solana_program::pubkey::Pubkey;

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
    fn test_engine_flow() {
        let mut engine = RiskEngine::new(default_params());
        
        // Init User
        let user_idx = engine.add_user(0).unwrap();
        engine.set_owner(user_idx, [1u8; 32]).unwrap();
        assert_eq!(engine.accounts[user_idx as usize].kind, AccountKind::User);

        // Deposit
        engine.deposit(user_idx, 1_000_000).unwrap();
        assert_eq!(engine.accounts[user_idx as usize].capital, 1_000_000);
        assert!(engine.check_conservation());

        // Withdraw half
        // Slot 0, price 100
        engine.withdraw(user_idx, 500_000, 0, 100_000_000).unwrap(); 
        assert_eq!(engine.accounts[user_idx as usize].capital, 500_000);
        assert!(engine.check_conservation());
    }
}