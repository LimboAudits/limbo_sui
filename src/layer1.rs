/// Layer 1: RECON ENGINE
/// Maps the entire codebase structure
/// Finds: entry points, capabilities, math ops, transfer calls
/// Feeds candidates to Layer 3 pattern scanner

use crate::types::{EntryPoint, MathOp, ReconResult, TransferCall};
use colored::*;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

pub fn run(move_files: &[PathBuf], contract_name: &str) -> ReconResult {
    println!("  {} Mapping codebase...", "◆".cyan());

    let mut entry_points = Vec::new();
    let mut capabilities = Vec::new();
    let mut math_operations = Vec::new();
    let mut transfer_calls = Vec::new();
    let mut total_lines = 0;

    for file_path in move_files {
        let source = match fs::read_to_string(file_path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        total_lines += source.lines().count();

        // Extract entry points
        let mut eps = extract_entry_points(&source, file_path);
        entry_points.append(&mut eps);

        // Extract capability types
        let mut caps = extract_capabilities(&source);
        capabilities.append(&mut caps);

        // Extract math operations
        let mut math = extract_math_operations(&source, file_path);
        math_operations.append(&mut math);

        // Extract transfer calls
        let mut transfers = extract_transfer_calls(&source, file_path);
        transfer_calls.append(&mut transfers);
    }

    // Deduplicate capabilities
    capabilities.sort();
    capabilities.dedup();

    println!(
        "  {} Recon: {} entry points, {} math ops, {} transfers, {} capabilities",
        "✓".green(),
        entry_points.len(),
        math_operations.len(),
        transfer_calls.len(),
        capabilities.len()
    );

    ReconResult {
        contract_name: contract_name.to_string(),
        move_files: move_files
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect(),
        entry_points,
        capabilities,
        math_operations,
        transfer_calls,
        total_lines,
    }
}

fn extract_entry_points(source: &str, file_path: &Path) -> Vec<EntryPoint> {
    let mut result = Vec::new();
    let fn_re =
        Regex::new(r"(public\s+(?:entry\s+)?fun|entry\s+fun)\s+(\w+)\s*(<[^>]*>)?\s*\(([^)]*)\)")
            .unwrap();

    for (line_num, line) in source.lines().enumerate() {
        if line.trim().starts_with("//") {
            continue;
        }

        if let Some(caps) = fn_re.captures(line) {
            let fn_name = caps.get(2).map_or("unknown", |m| m.as_str());
            let params = caps.get(4).map_or("", |m| m.as_str());

            // Skip test functions
            let context = get_surrounding_lines(source, line_num, 3);
            if context.contains("#[test") {
                continue;
            }

            result.push(EntryPoint {
                name: fn_name.to_string(),
                file: file_path.to_string_lossy().to_string(),
                line: (line_num + 1) as u32,
                is_public: line.contains("public"),
                params: params.to_string(),
                has_ctx: params.contains("TxContext"),
                has_cap: params.contains("Cap")
                    || params.contains("Admin")
                    || params.contains("Auth"),
            });
        }
    }
    result
}

fn extract_capabilities(source: &str) -> Vec<String> {
    let mut result = Vec::new();
    let cap_re = Regex::new(r"(?:public\s+)?struct\s+(\w*(?:Cap|Admin|Auth|Witness)\w*)\s+has")
        .unwrap();

    for line in source.lines() {
        if line.trim().starts_with("//") {
            continue;
        }
        if let Some(caps) = cap_re.captures(line) {
            if let Some(cap_name) = caps.get(1) {
                result.push(cap_name.as_str().to_string());
            }
        }
    }
    result
}

fn extract_math_operations(source: &str, file_path: &Path) -> Vec<MathOp> {
    let mut result = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.starts_with("//") || trimmed.starts_with("*") {
            continue;
        }

        // Detect integer types
        let operand_type = if trimmed.contains("u256") {
            "u256"
        } else if trimmed.contains("u128") {
            "u128"
        } else if trimmed.contains("u64") {
            "u64"
        } else if trimmed.contains("u32") {
            "u32"
        } else if trimmed.contains("u8") {
            "u8"
        } else {
            ""
        };

        // Detect arithmetic
        let has_add = trimmed.contains(" + ") || trimmed.contains("+=");
        let has_sub = trimmed.contains(" - ") || trimmed.contains("-=");
        let has_mul = trimmed.contains(" * ") || trimmed.contains("*=");
        let is_bit_shift = trimmed.contains(" << ") || trimmed.contains(" >> ");

        if (has_add || has_sub || has_mul || is_bit_shift) && !operand_type.is_empty() {
            let has_overflow_check = trimmed.contains("assert!")
                || trimmed.contains("checked_")
                || trimmed.contains("overflow")
                || get_surrounding_lines(source, line_num, 5).contains("assert!");

            result.push(MathOp {
                file: file_path.to_string_lossy().to_string(),
                line: (line_num + 1) as u32,
                operation: trimmed.to_string(),
                operand_type: operand_type.to_string(),
                has_overflow_check,
                is_bit_shift,
            });
        }
    }
    result
}

fn extract_transfer_calls(source: &str, file_path: &Path) -> Vec<TransferCall> {
    let mut result = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.starts_with("//") {
            continue;
        }

        let call_type = if trimmed.contains("transfer::public_transfer") {
            "public_transfer"
        } else if trimmed.contains("transfer::transfer") {
            "transfer"
        } else {
            continue;
        };

        let context = get_surrounding_lines(source, line_num, 10);
        let has_ownership_check = (context.contains("sender")
            && (context.contains("assert!") || context.contains("==")))
            || context.contains("owner");

        let in_init = get_surrounding_lines(source, line_num, 20).contains("fun init(");

        result.push(TransferCall {
            file: file_path.to_string_lossy().to_string(),
            line: (line_num + 1) as u32,
            call_type: call_type.to_string(),
            has_ownership_check,
            in_init,
        });
    }
    result
}

fn get_surrounding_lines(source: &str, center: usize, radius: usize) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let start = center.saturating_sub(radius);
    let end = std::cmp::min(center + radius, lines.len());
    lines[start..end].join("\n")
}
