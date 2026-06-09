/// Limbo Security Registry
/// Stores audit results on-chain on Sui
/// Every contract audited by limbo_sui gets an immutable on-chain record
module limbo::registry {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::event;
    use std::string::{Self, String};

    // ── Registry object (singleton) ──────────────────────────────────────

    public struct Registry has key {
        id: UID,
        total_audits: u64,
        auditor: address,
    }

    // ── Audit record (stored on-chain forever) ────────────────────────────

    public struct AuditRecord has key, store {
        id: UID,
        contract_name: String,
        repo_url: String,
        risk_score: u64,       // 0-100
        confirmed_count: u64,
        high_count: u64,
        medium_count: u64,
        false_positive_count: u64,
        audited_by: address,
        timestamp: u64,
        limbo_version: String,
    }

    // ── Events ────────────────────────────────────────────────────────────

    public struct AuditCompleted has copy, drop {
        record_id: address,
        contract_name: String,
        risk_score: u64,
        audited_by: address,
    }

    // ── Init ──────────────────────────────────────────────────────────────

    fun init(ctx: &mut TxContext) {
        let registry = Registry {
            id: object::new(ctx),
            total_audits: 0,
            auditor: tx_context::sender(ctx),
        };
        transfer::share_object(registry);
    }

    // ── Submit audit result on-chain ──────────────────────────────────────

    public entry fun submit_audit(
        registry: &mut Registry,
        contract_name: vector<u8>,
        repo_url: vector<u8>,
        risk_score: u64,
        confirmed_count: u64,
        high_count: u64,
        medium_count: u64,
        false_positive_count: u64,
        ctx: &mut TxContext
    ) {
        let record = AuditRecord {
            id: object::new(ctx),
            contract_name: string::utf8(contract_name),
            repo_url: string::utf8(repo_url),
            risk_score,
            confirmed_count,
            high_count,
            medium_count,
            false_positive_count,
            audited_by: tx_context::sender(ctx),
            timestamp: tx_context::epoch(ctx),
            limbo_version: string::utf8(b"0.2.0"),
        };

        // Emit event for indexers
        event::emit(AuditCompleted {
            record_id: object::uid_to_address(&record.id),
            contract_name: record.contract_name,
            risk_score: record.risk_score,
            audited_by: record.audited_by,
        });

        registry.total_audits = registry.total_audits + 1;

        // Transfer record to auditor — immutable proof of audit
        transfer::transfer(record, tx_context::sender(ctx));
    }

    // ── View functions ────────────────────────────────────────────────────

    public fun total_audits(registry: &Registry): u64 {
        registry.total_audits
    }

    public fun get_risk_score(record: &AuditRecord): u64 {
        record.risk_score
    }

    public fun get_contract_name(record: &AuditRecord): &String {
        &record.contract_name
    }
}
