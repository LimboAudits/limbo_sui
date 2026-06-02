use crate::types::{Finding, FindingStatus, Layer1Result, Layer2Result, Layer3Result, Severity};
use colored::*;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

struct Pattern {
    name: &'static str,
    severity: Severity,
    description: &'static str,
    check: fn(&str, &str) -> Option<(u32, String)>,
}

pub fn run(
    move_files: &[PathBuf],
    layer1: &Layer1Result,
    layer2: &Layer2Result,
) -> Layer3Result {
    println!("  {} Scanning {} Move file(s)...", "→".cyan(), move_files.len());

    let patterns = get_patterns();
    let mut confirmed: Vec<Finding> = Vec::new();
    let mut potential: Vec<Finding> = Vec::new();

    for file_path in move_files {
        let source = match fs::read_to_string(file_path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let file_name = file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        for pattern in &patterns {
            if let Some((line_num, detail)) = (pattern.check)(&source, &file_name) {
                let is_confirmed = is_confirmed_by_layers(
                    &file_name,
                    pattern.name,
                    layer1,
                    layer2,
                );

                let finding = Finding {
                    title: pattern.name.to_string(),
                    severity: pattern.severity.clone(),
                    status: if is_confirmed {
                        FindingStatus::Confirmed
                    } else {
                        FindingStatus::HighConfidence
                    },
                    file: file_path.to_string_lossy().to_string(),
                    line: Some(line_num),
                    description: format!("{}\n\nDetail: {}", pattern.description, detail),
                    raw_output: detail,
                    tools: vec!["limbo_pattern_scanner".to_string()],
                };

                if is_confirmed {
                    confirmed.push(finding);
                } else {
                    potential.push(finding);
                }
            }
        }
    }

    println!(
        "  {} Pattern scan: {} confirmed, {} potential",
        "✓".green(),
        confirmed.len(),
        potential.len()
    );

    Layer3Result { confirmed, potential }
}

fn get_patterns() -> Vec<Pattern> {
    vec![
        Pattern {
            name: "Integer Overflow Risk",
            severity: Severity::High,
            description: "Unchecked arithmetic on integer types can overflow, allowing attackers to manipulate balances or bypass logic. Move does not have SafeMath by default.",
            check: check_integer_overflow,
        },
        Pattern {
            name: "Missing Access Control",
            severity: Severity::Critical,
            description: "Public entry functions without signer parameter allow anyone to call privileged operations. This can lead to unauthorized state changes or fund theft.",
            check: check_missing_access_control,
        },
        Pattern {
            name: "Capability Leakage",
            severity: Severity::High,
            description: "Capability objects exposed in public return values or stored in public fields can be acquired by unauthorized parties, granting them elevated privileges.",
            check: check_capability_leakage,
        },
        Pattern {
            name: "Unchecked Object Ownership",
            severity: Severity::High,
            description: "Calling transfer::transfer without verifying object ownership allows transfer of objects the caller does not own, leading to theft.",
            check: check_unchecked_ownership,
        },
        Pattern {
            name: "Unsafe Public Transfer",
            severity: Severity::Medium,
            description: "transfer::public_transfer on objects without proper ownership validation may expose assets to unauthorized parties.",
            check: check_public_transfer,
        },
        Pattern {
            name: "Missing Abort on Error",
            severity: Severity::Medium,
            description: "Functions that should fail under certain conditions but do not abort allow execution to continue in invalid states.",
            check: check_missing_abort,
        },
    ]
}

// ─── Pattern Checks ────────────────────────────────────────────────────────

fn check_integer_overflow(source: &str, _file: &str) -> Option<(u32, String)> {
    // Look for arithmetic without overflow checks
    // Patterns: u64/u128 variables with +, -, * operations
    // that are NOT wrapped in assert! or checked_add etc.
    let re = Regex::new(r"(let\s+\w+\s*:\s*u(?:64|128|32|16|8)\s*=.*?[+\-\*].*?;)").unwrap();

    for (line_num, line) in source.lines().enumerate() {
        // Skip comments
        if line.trim().starts_with("//") {
            continue;
        }

        // Check for arithmetic operations on integer types
        if (line.contains("u64") || line.contains("u128") || line.contains("u32"))
            && (line.contains(" + ") || line.contains(" - ") || line.contains(" * "))
            && !line.contains("assert!")
            && !line.contains("checked_")
            && !line.contains("overflow")
        {
            // Make sure it's in a function body (has assignment or expression)
            if line.contains("=") || line.contains("(") {
                return Some((
                    (line_num + 1) as u32,
                    format!(
                        "Arithmetic operation on integer type without overflow check: `{}`",
                        line.trim()
                    ),
                ));
            }
        }

        // Also check for direct arithmetic in function calls
        if re.is_match(line) && !line.contains("assert!") {
            return Some((
                (line_num + 1) as u32,
                format!("Potentially unsafe integer arithmetic: `{}`", line.trim()),
            ));
        }
    }
    None
}

fn check_missing_access_control(source: &str, _file: &str) -> Option<(u32, String)> {
    // public entry fun without &signer or &mut TxContext parameter
    // Note: In Sui Move, access control uses TxContext + sender checks
    // or Capability objects — no signer like Aptos Move
    let entry_re = Regex::new(r"public\s+entry\s+fun\s+(\w+)\s*\(([^)]*)\)").unwrap();

    for (line_num, line) in source.lines().enumerate() {
        if line.trim().starts_with("//") {
            continue;
        }

        if let Some(caps) = entry_re.captures(line) {
            let fn_name = caps.get(1).map_or("", |m| m.as_str());
            let params = caps.get(2).map_or("", |m| m.as_str());

            // Check if it has ctx: &mut TxContext (standard Sui pattern)
            // or a capability parameter
            if !params.contains("TxContext")
                && !params.contains("Cap")
                && !params.contains("AdminCap")
                && !params.contains("capability")
            {
                return Some((
                    (line_num + 1) as u32,
                    format!(
                        "public entry fun `{}` has no TxContext or Capability parameter — anyone can call this",
                        fn_name
                    ),
                ));
            }

            // Has TxContext but no sender check in function body — check nearby lines
            if params.contains("TxContext") {
                let fn_body = get_function_body(source, line_num);
                if !fn_body.contains("tx_context::sender")
                    && !fn_body.contains("assert!")
                    && fn_body.contains("transfer")
                {
                    return Some((
                        (line_num + 1) as u32,
                        format!(
                            "public entry fun `{}` uses transfer but never checks tx_context::sender — missing authorization",
                            fn_name
                        ),
                    ));
                }
            }
        }
    }
    None
}

fn check_capability_leakage(source: &str, _file: &str) -> Option<(u32, String)> {
    // Look for capability types returned from public functions
    // Pattern: public fun ... : SomeCap
    let re = Regex::new(r"public\s+fun\s+(\w+)[^{]*\)\s*:\s*(\w*[Cc]ap\w*)").unwrap();

    for (line_num, line) in source.lines().enumerate() {
        if line.trim().starts_with("//") {
            continue;
        }

        if let Some(caps) = re.captures(line) {
            let fn_name = caps.get(1).map_or("", |m| m.as_str());
            let cap_type = caps.get(2).map_or("", |m| m.as_str());

            return Some((
                (line_num + 1) as u32,
                format!(
                    "public fun `{}` returns capability type `{}` — capability may be leaked to unauthorized callers",
                    fn_name, cap_type
                ),
            ));
        }
    }
    None
}

fn check_unchecked_ownership(source: &str, _file: &str) -> Option<(u32, String)> {
    // transfer::transfer called without ownership validation
    for (line_num, line) in source.lines().enumerate() {
        if line.trim().starts_with("//") {
            continue;
        }

        if (line.contains("transfer::transfer") || line.contains("transfer("))
            && !line.contains("assert!")
        {
            // Check if the surrounding context has any ownership check
            let context = get_surrounding_lines(source, line_num, 5);
            if !context.contains("tx_context::sender")
                && !context.contains("assert!")
                && !context.contains("owner")
            {
                return Some((
                    (line_num + 1) as u32,
                    format!(
                        "transfer call without ownership validation: `{}`",
                        line.trim()
                    ),
                ));
            }
        }
    }
    None
}

fn check_public_transfer(source: &str, _file: &str) -> Option<(u32, String)> {
    for (line_num, line) in source.lines().enumerate() {
        if line.trim().starts_with("//") {
            continue;
        }

        if line.contains("transfer::public_transfer") {
            let context = get_surrounding_lines(source, line_num, 3);
            if !context.contains("assert!") && !context.contains("sender") {
                return Some((
                    (line_num + 1) as u32,
                    format!(
                        "public_transfer without sender validation: `{}`",
                        line.trim()
                    ),
                ));
            }
        }
    }
    None
}

fn check_missing_abort(source: &str, _file: &str) -> Option<(u32, String)> {
    // Functions with if conditions but no abort/assert in critical paths
    // This is a heuristic — look for if without else + abort in entry functions
    let entry_re = Regex::new(r"entry\s+fun\s+(\w+)").unwrap();

    for (line_num, line) in source.lines().enumerate() {
        if line.trim().starts_with("//") {
            continue;
        }

        if entry_re.is_match(line) {
            let body = get_function_body(source, line_num);
            // Has conditional logic but no error handling
            if body.contains("if (")
                && !body.contains("assert!")
                && !body.contains("abort")
                && body.len() > 100
            {
                let fn_name = entry_re
                    .captures(line)
                    .and_then(|c| c.get(1))
                    .map_or("unknown", |m| m.as_str());

                return Some((
                    (line_num + 1) as u32,
                    format!(
                        "entry fun `{}` has conditional logic but no assert!/abort — invalid states may not be caught",
                        fn_name
                    ),
                ));
            }
        }
    }
    None
}

// ─── Helpers ───────────────────────────────────────────────────────────────

fn get_function_body(source: &str, start_line: usize) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mut body = String::new();
    let mut depth = 0;
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
        // Don't go further than 100 lines
        if body.lines().count() > 100 {
            break;
        }
    }
    body
}

fn get_surrounding_lines(source: &str, center: usize, radius: usize) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let start = center.saturating_sub(radius);
    let end = std::cmp::min(center + radius, lines.len());
    lines[start..end].join("\n")
}

fn is_confirmed_by_layers(
    file_name: &str,
    pattern_name: &str,
    layer1: &Layer1Result,
    layer2: &Layer2Result,
) -> bool {
    // Check if Layer 1 or Layer 2 also flagged something in the same file
    let l1_hit = layer1.errors.iter().any(|e| {
        e.file.contains(file_name)
            || classify_pattern_match(pattern_name, &e.error_type)
    });

    let l2_hit = layer2.failures.iter().any(|f| {
        f.message.to_lowercase().contains(&pattern_name.to_lowercase())
            || f.module.contains(file_name.trim_end_matches(".move"))
    });

    l1_hit || l2_hit
}

fn classify_pattern_match(pattern: &str, error_type: &str) -> bool {
    match (pattern, error_type.as_ref()) {
        ("Integer Overflow Risk", "IntegerOverflow") => true,
        ("Missing Access Control", "AccessControl") => true,
        ("Capability Leakage", "CapabilityLeak") => true,
        _ => false,
    }
}
