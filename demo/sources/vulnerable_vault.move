/// VulnerableVault — Demo contract for limbo_sui
/// WARNING: This contract is INTENTIONALLY VULNERABLE
/// Used to demonstrate limbo_sui's detection capabilities
module demo::vulnerable_vault {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use sui::balance::{Self, Balance};

    /// The vault object holding funds
    public struct Vault has key {
        id: UID,
        balance: Balance<SUI>,
        owner: address,
        total_deposited: u64,
    }

    /// Admin capability — VULN: returned from public function
    public struct AdminCap has key, store {
        id: UID,
    }

    /// Initialize vault
    fun init(ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// VULNERABILITY 1: Missing access control
    /// Anyone can call this — no capability check
    public fun create_vault(ctx: &mut TxContext) {
        let vault = Vault {
            id: object::new(ctx),
            balance: balance::zero(),
            owner: tx_context::sender(ctx),
            total_deposited: 0,
        };
        transfer::transfer(vault, tx_context::sender(ctx));
    }

    /// VULNERABILITY 2: Integer overflow
    /// total_deposited can overflow with large amounts
    public fun deposit(
        vault: &mut Vault,
        payment: Coin<SUI>,
        _ctx: &mut TxContext
    ) {
        let amount = coin::value(&payment);
        // VULN: unchecked addition — overflows at u64::MAX
        vault.total_deposited = vault.total_deposited + amount;
        balance::join(&mut vault.balance, coin::into_balance(payment));
    }

    /// VULNERABILITY 3: Unchecked ownership on transfer
    /// No check that caller owns the vault
    public fun withdraw_all(
        vault: Vault,
        ctx: &mut TxContext
    ) {
        let Vault { id, balance, owner: _, total_deposited: _ } = vault;
        object::delete(id);
        // VULN: no check that tx_context::sender == owner
        let coin = coin::from_balance(balance, ctx);
        transfer::public_transfer(coin, tx_context::sender(ctx));
    }

    /// VULNERABILITY 4: Capability leakage
    /// Returns AdminCap from a public function
    public fun get_admin_cap(ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }

    /// VULNERABILITY 5: Missing abort on invalid state
    public fun withdraw_partial(
        vault: &mut Vault,
        amount: u64,
        ctx: &mut TxContext
    ) {
        // VULN: no assert!(amount <= balance)
        // VULN: no check that sender == vault.owner
        if (amount <= balance::value(&vault.balance)) {
            let withdrawn = balance::split(&mut vault.balance, amount);
            let coin = coin::from_balance(withdrawn, ctx);
            transfer::public_transfer(coin, tx_context::sender(ctx));
        }
        // Silently does nothing if amount > balance
    }
}
