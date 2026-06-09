/// VulnerableVault — Demo contract for limbo_sui
/// WARNING: INTENTIONALLY VULNERABLE
/// Contains all vulnerability classes limbo_sui detects
module demo::vulnerable_vault {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use sui::balance::{Self, Balance};

    // ── Structs ──────────────────────────────────────────────────────────

    public struct Vault has key {
        id: UID,
        balance: Balance<SUI>,
        owner: address,
        total_deposited: u64,
    }

    /// VULN 4: AdminCap is a capability type
    public struct AdminCap has key, store {
        id: UID,
    }

    // ── Init ─────────────────────────────────────────────────────────────

    fun init(ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    // ── VULNERABILITY 1: Missing access control ──────────────────────────
    /// No TxContext, no Capability — anyone can call this
    public fun create_vault(ctx: &mut TxContext) {
        let vault = Vault {
            id: object::new(ctx),
            balance: balance::zero(),
            owner: tx_context::sender(ctx),
            total_deposited: 0,
        };
        transfer::transfer(vault, tx_context::sender(ctx));
    }

    // ── VULNERABILITY 2: Integer overflow ────────────────────────────────
    /// total_deposited addition has no overflow check
    public fun deposit(
        vault: &mut Vault,
        payment: Coin<SUI>,
        _ctx: &mut TxContext
    ) {
        let amount = coin::value(&payment);
        // VULN: unchecked u64 addition
        vault.total_deposited = vault.total_deposited + amount;
        balance::join(&mut vault.balance, coin::into_balance(payment));
    }

    // ── VULNERABILITY 3: Unchecked ownership ─────────────────────────────
    /// No check that caller == vault.owner
    public fun withdraw_all(
        vault: Vault,
        ctx: &mut TxContext
    ) {
        let Vault { id, balance, owner: _, total_deposited: _ } = vault;
        object::delete(id);
        // VULN: no assert!(tx_context::sender(ctx) == owner)
        let coin = coin::from_balance(balance, ctx);
        transfer::public_transfer(coin, tx_context::sender(ctx));
    }

    // ── VULNERABILITY 4: Capability leakage ──────────────────────────────
    /// Public function returns AdminCap — anyone can get admin
    public fun get_admin_cap(ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }

    // ── VULNERABILITY 5: Missing abort on invalid state ──────────────────
    /// Has if condition but never aborts — silent failure
    public fun withdraw_partial(
        vault: &mut Vault,
        amount: u64,
        ctx: &mut TxContext
    ) {
        // VULN: no assert!(tx_context::sender(ctx) == vault.owner)
        // VULN: no assert!(amount <= balance) — silent skip instead
        if (amount <= balance::value(&vault.balance)) {
            let withdrawn = balance::split(&mut vault.balance, amount);
            let coin = coin::from_balance(withdrawn, ctx);
            transfer::public_transfer(coin, tx_context::sender(ctx));
        }
        // Silently does nothing if amount > balance
    }
}
