use crate::types::{Finding, FindingStatus, Layer1Result, Layer2Result, Layer3Result, Severity};
use colored::*;
use std::fs;
use std::path::{Path, PathBuf};

struct Pattern {
    name: &'static str,
    severity: Severity,
    description: &'static str,
    check: fn(&str, &Path) -> Vec<(u32, String)>,
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

        for pattern in &patterns {
            let hits = (pattern.check)(&source, file_path);
            for (line_num, detail) in hits {
                let is_confirmed = is_confirmed_by_layers(
                    &file_path.to_string_lossy(),
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

    // Deduplicate by title + file + line
    confirmed.dedup_by(|a, b| a.title == b.title && a.file == b.file && a.line == b.line);
    potential.dedup_by(|a, b| a.title == b.title && a.file == b.file && a.line == b.line);

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
            description: "Unchecked arithmetic on integer types can overflow, allowing attackers to manipulate balances or bypass logic.",
            check: check_integer_overflow,
        },
        Pattern {
            name: "Missing Access Control",
            severity: Severity::Critical,
            description: "Public functions without proper authorization checks allow anyone to call privileged operations.",
            check: check_missing_access_control,
        },
        Pattern {
            name: "Capability Leakage",
            severity: Severity::High,
            description: "Capability objects exposed in public return values can be acquired by unauthorized parties.",
            check: check_capability_leakage,
        },
        Pattern {
            name: "Unchecked Object Ownership",
            severity: Severity::High,
            description: "Calling transfer without verifying object ownership allows transfer of objects the caller does not own.",
            check: check_unchecked_ownership,
        },
        Pattern {
            name: "Missing Abort on Error",
            severity: Severity::Medium,
            description: "Functions with conditional logic but no abort/assert allow execution in invalid states.",
            check: check_missing_abort,
        },
    ]
}

// ─── Pattern Checks ─────────────────────────────────────────────────────────

fn check_integer_overflow(source: &str, _file: &Path) -> Vec<(u32, String)> {
    let mut hits = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();

        // Skip comments
        if trimmed.starts_with("//") || trimmed.starts_with("*") {
            continue;
        }

        // Look for arithmetic on integer types without checks
        let has_int_type = trimmed.contains("u64")
            || trimmed.contains("u128")
            || trimmed.contains("u32")
            || trimmed.contains("u8")
            || trimmed.contains("u16");

        let has_arithmetic = trimmed.contains(" + ")
            || trimmed.contains(" - ")
            || trimmed.contains(" * ")
            || trimmed.contains("+=")
            || trimmed.contains("-=")
            || trimmed.contains("*=");

        let has_check = trimmed.contains("assert!")
            || trimmed.contains("checked_")
            || trimmed.contains("overflow")
            || trimmed.contains("/ 10_000") // royalty calc pattern is intentional
            || trimmed.contains("as u128"); // casting up is safe

        if has_arithmetic && !has_check {
            // Check surrounding context for integer type declarations
            let context = get_surrounding_lines(source, line_num, 10);
            if context.contains("u64")
                || context.contains("u128")
                || context.contains("u32")
                || has_int_type
            {
                hits.push((
                    (line_num + 1) as u32,
                    format!("Unchecked arithmetic operation: `{}`", trimmed),
                ));
            }
        }
    }

    // Only return first hit per function to avoid noise
    hits.truncate(3);
    hits
}

fn check_missing_access_control(source: &str, _file: &Path) -> Vec<(u32, String)> {
    let mut hits = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.starts_with("//") {
            continue;
        }

        // Match public fun without capability or TxContext sender check
        if (trimmed.contains("public fun ") || trimmed.contains("public entry fun "))
            && trimmed.contains("(")
            && !trimmed.contains("//")
        {
            // Skip init functions — they're safe
            if trimmed.contains("fun init(") {
                continue;
            }

            let params = extract_params(trimmed);
            let fn_name = extract_fn_name(trimmed);

            // No TxContext AND no capability parameter
            if !params.contains("TxContext")
                && !params.contains("Cap")
                && !params.contains("Admin")
                && !params.contains("Auth")
            {
                // Check if function body has transfer or state mutation
                let body = get_function_body(source, line_num);
                if body.contains("transfer")
                    || body.contains("balance")
                    || body.contains("coin")
                    || body.contains("emit")
                {
                    hits.push((
                        (line_num + 1) as u32,
                        format!(
                            "public fun `{}` has no access control and performs state changes",
                            fn_name
                        ),
                    ));
                }
            }

            // Has TxContext but never checks sender
            if params.contains("TxContext") {
                let body = get_function_body(source, line_num);
                if !body.contains("sender")
                    && !body.contains("assert!")
                    && !body.contains("Cap")
                    && (body.contains("transfer::transfer")
                        || body.contains("transfer::public_transfer"))
                {
                    hits.push((
                        (line_num + 1) as u32,
                        format!(
                            "public fun `{}` transfers assets but never checks sender identity",
                            fn_name
                        ),
                    ));
                }
            }
        }
    }

    hits
}

fn check_capability_leakage(source: &str, _file: &Path) -> Vec<(u32, String)> {
    let mut hits = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.starts_with("//") {
            continue;
        }

        // public fun that RETURNS a Cap type
        if trimmed.contains("public fun ")
            && trimmed.contains(")")
            && trimmed.contains(":")
        {
            let after_paren = trimmed.split(')').last().unwrap_or("");
            if after_paren.contains("Cap")
                || after_paren.contains("Admin")
                || after_paren.contains("Auth")
                || after_paren.contains("Witness")
            {
                let fn_name = extract_fn_name(trimmed);
                hits.push((
                    (line_num + 1) as u32,
                    format!(
                        "public fun `{}` returns a capability type — any caller can obtain elevated privileges",
                        fn_name
                    ),
                ));
            }
        }
    }

    hits
}

fn check_unchecked_ownership(source: &str, _file: &Path) -> Vec<(u32, String)> {
    let mut hits = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.starts_with("//") {
            continue;
        }

        if trimmed.contains("transfer::transfer(")
            || trimmed.contains("transfer::public_transfer(")
        {
            // Check surrounding context for ownership validation
            let context = get_surrounding_lines(source, line_num, 8);

            let has_ownership_check = context.contains("sender")
                && (context.contains("assert!")
                    || context.contains("==")
                    || context.contains("owner"));

            // Skip init() — safe pattern
            let in_init = get_surrounding_lines(source, line_num, 15).contains("fun init(");

            if !has_ownership_check && !in_init {
                hits.push((
                    (line_num + 1) as u32,
                    format!(
                        "Transfer without ownership validation: `{}`",
                        trimmed
                    ),
                ));
            }
        }
    }

    hits
}

fn check_missing_abort(source: &str, _file: &Path) -> Vec<(u32, String)> {
    let mut hits = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.starts_with("//") {
            continue;
        }

        // Public functions with if but no abort/assert
        if (trimmed.contains("public fun ") || trimmed.contains("public entry fun "))
            && !trimmed.contains("fun init(")
        {
            let body = get_function_body(source, line_num);
            let fn_name = extract_fn_name(trimmed);

            if body.contains("if (")
                && !body.contains("assert!")
                && !body.contains("abort")
                && body.len() > 80
                && (body.contains("transfer") || body.contains("balance") || body.contains("coin"))
            {
                hits.push((
                    (line_num + 1) as u32,
                    format!(
                        "public fun `{}` has conditional logic with no abort/assert — invalid states not caught",
                        fn_name
                    ),
                ));
            }
        }
    }

    hits
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn extract_fn_name(line: &str) -> String {
    // Extract name from "public fun name(" or "public entry fun name("
    let after_fun = if let Some(pos) = line.find("fun ") {
        &line[pos + 4..]
    } else {
        return "unknown".to_string();
    };

    after_fun
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

fn extract_params(line: &str) -> String {
    if let (Some(start), Some(end)) = (line.find('('), line.find(')')) {
        line[start + 1..end].to_string()
    } else {
        String::new()
    }
}

fn get_function_body(source: &str, start_line: usize) -> String {
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
        if body.lines().count() > 80 {
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
    file_path: &str,
    pattern_name: &str,
    layer1: &Layer1Result,
    layer2: &Layer2Result,
) -> bool {
    let file_name = std::path::Path::new(file_path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let l1_hit = layer1.errors.iter().any(|e| {
        e.file.contains(&file_name) || classify_pattern_match(pattern_name, &e.error_type)
    });

    let l2_hit = layer2.failures.iter().any(|f| {
        f.module.contains(file_name.trim_end_matches(".move"))
    });

    l1_hit || l2_hit
}

fn classify_pattern_match(pattern: &str, error_type: &str) -> bool {
    matches!(
        (pattern, error_type),
        ("Integer Overflow Risk", "IntegerOverflow")
            | ("Missing Access Control", "AccessControl")
            | ("Capability Leakage", "CapabilityLeak")
    )
}
