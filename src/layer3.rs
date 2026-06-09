/// Layer 3: DEEP PATTERN SCANNER
/// Based on real Move hacks and CVE research:
/// - Cetus $223M overflow (May 2025)
/// - MWC taxonomy (37 vulnerability types)
/// - MoveScan research (20,778 vulns across 37,302 contracts)

use crate::types::{
    ConfidenceLevel, Finding, MathOp, ReconResult, Severity, TransferCall,
};
use colored::*;
use std::fs;
use std::path::PathBuf;

pub fn run(move_files: &[PathBuf], recon: &ReconResult) -> Vec<Finding> {
    println!("  {} Running deep pattern scan...", "◆".cyan());

    let mut findings = Vec::new();
    let mut finding_id = 1u32;

    // ── Pattern 1: Cetus-style bit shift overflow ──────────────────────────
    for math_op in &recon.math_operations {
        if math_op.is_bit_shift && !math_op.has_overflow_check {
            let source = fs::read_to_string(&math_op.file).unwrap_or_default();
            let snippet = get_line(&source, math_op.line);

            // Cetus pattern: u256 << without proper mask check
            let is_cetus_pattern = (math_op.operand_type == "u256"
                || math_op.operand_type == "u128")
                && math_op.operation.contains("<<");

            findings.push(Finding {
                id: format!("LIMBO-{:03}", finding_id),
                title: if is_cetus_pattern {
                    "Cetus-Pattern Bit Shift Overflow".to_string()
                } else {
                    "Bit Shift Overflow Risk".to_string()
                },
                severity: if is_cetus_pattern {
                    Severity::Critical
                } else {
                    Severity::High
                },
                confidence: ConfidenceLevel::High,
                file: math_op.file.clone(),
                line: Some(math_op.line),
                code_snippet: snippet,
                description: if is_cetus_pattern {
                    "Left shift on u256/u128 without proper overflow guard. This is the exact vulnerability class that caused the $223M Cetus hack on May 22, 2025. The checked_shlw pattern — using > instead of >= for the mask check — allows attackers to silently overflow fixed-point math.".to_string()
                } else {
                    "Bit shift operation without overflow check. Shift operations on large integers can overflow silently if the mask check uses wrong bounds.".to_string()
                },
                exploit_scenario: "Attacker crafts a transaction with extreme input values that trigger the bit shift to overflow. The overflow corrupts internal accounting (e.g. liquidity calculations), allowing attacker to withdraw more assets than deposited. Cetus lost $223M this way.".to_string(),
                recommendation: "Use checked arithmetic with correct mask bounds. For u256 left shift by 64 bits, the overflow guard mask should be `1 << 192`, not `1 << 256 - 1`. Use >= not > in the comparison.".to_string(),
                cve_class: "Integer Overflow / Bit Shift".to_string(),
                proof: None,
            });
            finding_id += 1;
        }
    }

    // ── Pattern 2: Unchecked arithmetic overflow ───────────────────────────
    for math_op in &recon.math_operations {
        if !math_op.is_bit_shift && !math_op.has_overflow_check {
            let source = fs::read_to_string(&math_op.file).unwrap_or_default();
            let snippet = get_line(&source, math_op.line);

            // Only flag meaningful operations (balance, amount, value related)
            let context = get_surrounding_lines_from_source(
                &source,
                math_op.line as usize - 1,
                5,
            );
            let is_financial = context.contains("balance")
                || context.contains("amount")
                || context.contains("value")
                || context.contains("coin")
                || context.contains("liquidity")
                || context.contains("deposit")
                || context.contains("withdraw");

            if is_financial {
                findings.push(Finding {
                    id: format!("LIMBO-{:03}", finding_id),
                    title: "Unchecked Integer Arithmetic".to_string(),
                    severity: Severity::High,
                    confidence: ConfidenceLevel::High,
                    file: math_op.file.clone(),
                    line: Some(math_op.line),
                    code_snippet: snippet,
                    description: format!(
                        "Unchecked {} arithmetic on financial value. While Move aborts on overflow by default, an unhandled abort causes denial of service. In custom math libraries (like Cetus's integer-mate), overflow behavior may differ.",
                        math_op.operand_type
                    ),
                    exploit_scenario: "Attacker deposits maximum u64 value, causing overflow in balance tracking. Contract either aborts (DoS) or in custom math contexts, wraps around corrupting accounting.".to_string(),
                    recommendation: "Add explicit bounds check before arithmetic: `assert!(amount <= MAX_AMOUNT - vault.balance, ERR_OVERFLOW);`".to_string(),
                    cve_class: "Integer Overflow".to_string(),
                    proof: None,
                });
                finding_id += 1;
            }
        }
    }

    // ── Pattern 3: Missing access control on entry points ─────────────────
    for entry in &recon.entry_points {
        if entry.is_public && !entry.has_ctx && !entry.has_cap {
            let source = fs::read_to_string(&entry.file).unwrap_or_default();
            let body = get_function_body_from_source(&source, entry.line as usize - 1);

            let is_dangerous = body.contains("transfer")
                || body.contains("balance")
                || body.contains("coin")
                || body.contains("withdraw")
                || body.contains("mint")
                || body.contains("burn");

            if is_dangerous && entry.name != "init" {
                let snippet = get_line(&source, entry.line);
                findings.push(Finding {
                    id: format!("LIMBO-{:03}", finding_id),
                    title: "Missing Access Control".to_string(),
                    severity: Severity::Critical,
                    confidence: ConfidenceLevel::High,
                    file: entry.file.clone(),
                    line: Some(entry.line),
                    code_snippet: snippet,
                    description: format!(
                        "Public function `{}` has no TxContext or Capability parameter but performs privileged operations. Any address can call this function.",
                        entry.name
                    ),
                    exploit_scenario: format!(
                        "Attacker calls `{}` directly. Without authorization checks, the function executes state changes (transfers, mints, withdrawals) on behalf of any caller.",
                        entry.name
                    ),
                    recommendation: "Add `_cap: &AdminCap` or `ctx: &mut TxContext` with sender check: `assert!(tx_context::sender(ctx) == owner, ERR_UNAUTHORIZED);`".to_string(),
                    cve_class: "Access Control".to_string(),
                    proof: None,
                });
                finding_id += 1;
            }
        }

        // Has TxContext but no sender check and transfers
        if entry.is_public && entry.has_ctx && !entry.has_cap && entry.name != "init" {
            let source = fs::read_to_string(&entry.file).unwrap_or_default();
            let body = get_function_body_from_source(&source, entry.line as usize - 1);

            let transfers_assets = body.contains("transfer::transfer")
                || body.contains("transfer::public_transfer");
            let checks_sender = body.contains("sender")
                && (body.contains("assert!") || body.contains("=="));

            if transfers_assets && !checks_sender {
                let snippet = get_line(&source, entry.line);
                findings.push(Finding {
                    id: format!("LIMBO-{:03}", finding_id),
                    title: "Unauthorized Asset Transfer".to_string(),
                    severity: Severity::Critical,
                    confidence: ConfidenceLevel::High,
                    file: entry.file.clone(),
                    line: Some(entry.line),
                    code_snippet: snippet,
                    description: format!(
                        "Public function `{}` transfers assets without verifying sender is the owner. Anyone can trigger this transfer.",
                        entry.name
                    ),
                    exploit_scenario: format!(
                        "Attacker calls `{}` — function transfers assets to tx_context::sender(ctx) without checking caller is authorized owner.",
                        entry.name
                    ),
                    recommendation: "Add ownership check: `assert!(tx_context::sender(ctx) == object.owner, ERR_NOT_OWNER);`".to_string(),
                    cve_class: "Access Control".to_string(),
                    proof: None,
                });
                finding_id += 1;
            }
        }
    }

    // ── Pattern 4: Capability leakage ─────────────────────────────────────
    for entry in &recon.entry_points {
        if entry.is_public {
            let source = fs::read_to_string(&entry.file).unwrap_or_default();
            let fn_line = get_line(&source, entry.line);

            // Check if function returns a capability type
            let after_params = fn_line.split(')').last().unwrap_or("");
            let returns_cap = recon.capabilities.iter().any(|cap| {
                after_params.contains(cap.as_str())
            }) || after_params.contains("Cap")
                || after_params.contains("Admin")
                || after_params.contains("Witness");

            if returns_cap {
                findings.push(Finding {
                    id: format!("LIMBO-{:03}", finding_id),
                    title: "Capability Leakage".to_string(),
                    severity: Severity::High,
                    confidence: ConfidenceLevel::High,
                    file: entry.file.clone(),
                    line: Some(entry.line),
                    code_snippet: fn_line.clone(),
                    description: format!(
                        "Public function `{}` returns a capability object. Any caller can acquire this capability and use it to invoke privileged operations.",
                        entry.name
                    ),
                    exploit_scenario: format!(
                        "Attacker calls `{}`, receives capability object. Uses capability to call admin functions: withdraw_all, mint, pause, upgrade.",
                        entry.name
                    ),
                    recommendation: "Never return capability objects from public functions. Transfer capabilities only in `init()` to the deployer. Use capability as function argument, not return value.".to_string(),
                    cve_class: "Capability Misuse".to_string(),
                    proof: None,
                });
                finding_id += 1;
            }
        }
    }

    // ── Pattern 5: Unchecked object ownership ─────────────────────────────
    for transfer in &recon.transfer_calls {
        if !transfer.has_ownership_check && !transfer.in_init {
            let source = fs::read_to_string(&transfer.file).unwrap_or_default();
            let snippet = get_line(&source, transfer.line);

            findings.push(Finding {
                id: format!("LIMBO-{:03}", finding_id),
                title: "Unchecked Object Ownership".to_string(),
                severity: Severity::High,
                confidence: ConfidenceLevel::High,
                file: transfer.file.clone(),
                line: Some(transfer.line),
                code_snippet: snippet,
                description: format!(
                    "Call to `{}` without verifying the caller owns the object being transferred. In Sui's object model, this can allow an attacker to initiate transfer of objects they don't own.",
                    transfer.call_type
                ),
                exploit_scenario: "Attacker passes object ID of victim's asset to a public function. Without ownership check, contract calls transfer on victim's object, sending it to attacker.".to_string(),
                recommendation: "Before transfer, verify ownership: `assert!(object.owner == tx_context::sender(ctx), ERR_NOT_OWNER);` Or pass object by mutable reference which implicitly enforces ownership.".to_string(),
                cve_class: "Ownership Violation".to_string(),
                proof: None,
            });
            finding_id += 1;
        }
    }

    // ── Pattern 6: Flash loan + liquidity math (DeFi specific) ────────────
    for file_path in move_files {
        let source = match fs::read_to_string(file_path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let file_str = file_path.to_string_lossy().to_string();
        let is_defi = source.contains("liquidity")
            || source.contains("pool")
            || source.contains("swap")
            || source.contains("amm")
            || source.contains("clmm");

        if is_defi {
            // Look for tick/price math without bounds
            for (line_num, line) in source.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") {
                    continue;
                }

                let is_price_math = (trimmed.contains("tick")
                    || trimmed.contains("sqrt_price")
                    || trimmed.contains("price_diff"))
                    && (trimmed.contains(" * ") || trimmed.contains(" << "));

                let no_bounds = !trimmed.contains("assert!")
                    && !get_surrounding_lines_from_source(&source, line_num, 3)
                        .contains("assert!");

                if is_price_math && no_bounds {
                    findings.push(Finding {
                        id: format!("LIMBO-{:03}", finding_id),
                        title: "DeFi Price Manipulation Risk".to_string(),
                        severity: Severity::Critical,
                        confidence: ConfidenceLevel::High,
                        file: file_str.clone(),
                        line: Some((line_num + 1) as u32),
                        code_snippet: trimmed.to_string(),
                        description: "Tick/price math without bounds validation in AMM/liquidity context. This pattern matches the Cetus $223M exploit where manipulated pool prices were used to drain reserves.".to_string(),
                        exploit_scenario: "Attacker executes flash swap to create extreme price difference. Combined with unvalidated tick math, this allows minting disproportionate liquidity for minimal token input.".to_string(),
                        recommendation: "Add strict bounds validation on all price/tick inputs. Validate sqrt_price_diff cannot exceed safe thresholds. Use checked arithmetic throughout liquidity math.".to_string(),
                        cve_class: "Oracle / Price Manipulation".to_string(),
                        proof: None,
                    });
                    finding_id += 1;
                }
            }
        }
    }

    // ── Pattern 7: Missing abort on conditional logic ─────────────────────
    for entry in &recon.entry_points {
        if entry.is_public && entry.name != "init" {
            let source = fs::read_to_string(&entry.file).unwrap_or_default();
            let body = get_function_body_from_source(&source, entry.line as usize - 1);

            let has_if = body.contains("if (");
            let has_abort = body.contains("assert!") || body.contains("abort");
            let has_financial = body.contains("balance")
                || body.contains("coin")
                || body.contains("transfer");

            if has_if && !has_abort && has_financial && body.len() > 100 {
                let snippet = get_line(&source, entry.line);
                findings.push(Finding {
                    id: format!("LIMBO-{:03}", finding_id),
                    title: "Missing Abort on Invalid State".to_string(),
                    severity: Severity::Medium,
                    confidence: ConfidenceLevel::Medium,
                    file: entry.file.clone(),
                    line: Some(entry.line),
                    code_snippet: snippet,
                    description: format!(
                        "Function `{}` has conditional logic affecting financial operations but never aborts. Invalid states are silently ignored instead of reverting the transaction.",
                        entry.name
                    ),
                    exploit_scenario: "Attacker triggers the condition branch that should fail. Without abort, execution continues in invalid state. Assets may be transferred under wrong conditions.".to_string(),
                    recommendation: "Replace silent `if` branches with `assert!`: `assert!(condition, ERR_INVALID_STATE);` so invalid states revert the entire transaction.".to_string(),
                    cve_class: "Logic Error".to_string(),
                    proof: None,
                });
                finding_id += 1;
            }
        }
    }

    // Deduplicate: same title + file + line
    findings.dedup_by(|a, b| {
        a.title == b.title && a.file == b.file && a.line == b.line
    });

    println!(
        "  {} Pattern scan: {} findings",
        "✓".green(),
        findings.len()
    );

    findings
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn get_line(source: &str, line_num: u32) -> String {
    source
        .lines()
        .nth((line_num as usize).saturating_sub(1))
        .unwrap_or("")
        .trim()
        .to_string()
}

fn get_surrounding_lines_from_source(source: &str, center: usize, radius: usize) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let start = center.saturating_sub(radius);
    let end = std::cmp::min(center + radius, lines.len());
    lines[start..end].join("\n")
}

fn get_function_body_from_source(source: &str, start_line: usize) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mut body = String::new();
    let mut depth = 0i32;
    let mut started = false;

    for line in lines.iter().skip(start_line) {
        for ch in line.chars() {
            if ch == '{' {
                depth += 1;
                started = true;
            } else if ch == '}' {
                depth -= 1;
            }
        }
        body.push_str(line);
        body.push('\n');

        if started && depth == 0 {
            break;
        }
        if body.lines().count() > 100 {
            break;
        }
    }
    body
}
