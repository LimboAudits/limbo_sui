use crate::types::{BuildError, Layer1Result};
use anyhow::Result;
use colored::*;
use std::path::Path;
use std::process::Command;

pub fn run(project_path: &Path) -> Result<Layer1Result> {
    println!("  {} Running sui move build...", "→".cyan());

    // Find the sui binary — bundled first, then system
    let sui_bin = find_sui_binary();

    let output = Command::new(&sui_bin)
        .args(["move", "build"])
        .current_dir(project_path)
        .output();

    match output {
        Err(e) => {
            // sui not found at all
            println!("  {} sui binary not found: {}", "✗".red(), e);
            return Ok(Layer1Result {
                success: false,
                errors: vec![BuildError {
                    file: "N/A".to_string(),
                    line: None,
                    message: format!("sui CLI not found: {}", e),
                    error_type: "MissingTool".to_string(),
                }],
                raw: String::new(),
            });
        }
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let raw = format!("{}\n{}", stdout, stderr);
            let success = out.status.success();

            if success {
                println!("  {} Build passed", "✓".green());
                return Ok(Layer1Result {
                    success: true,
                    errors: vec![],
                    raw,
                });
            }

            println!("  {} Build failed — parsing errors...", "!".yellow());

            let errors = parse_build_errors(&raw);
            println!("  {} Found {} build error(s)", "→".cyan(), errors.len());

            Ok(Layer1Result {
                success: false,
                errors,
                raw,
            })
        }
    }
}

fn find_sui_binary() -> String {
    // 1. Check bundled binary
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()));

    if let Some(dir) = exe_dir {
        let bundled = dir.join("bin").join("sui");
        if bundled.exists() {
            return bundled.to_string_lossy().to_string();
        }
    }

    // 2. Fall back to system sui
    "sui".to_string()
}

fn parse_build_errors(raw: &str) -> Vec<BuildError> {
    let mut errors = Vec::new();

    for line in raw.lines() {
        // Sui Move error format:
        // error[E####]: message
        //  --> sources/file.move:LINE:COL
        if line.trim_start().starts_with("error") {
            let message = line
                .split(':')
                .skip(1)
                .collect::<Vec<_>>()
                .join(":")
                .trim()
                .to_string();

            let error_type = classify_error_string(&message);

            errors.push(BuildError {
                file: extract_file_from_context(raw, line),
                line: extract_line_number(raw, line),
                message,
                error_type,
            });
        }
    }

    // Deduplicate
    errors.dedup_by(|a, b| a.message == b.message);
    errors
}

fn extract_file_from_context(raw: &str, error_line: &str) -> String {
    // Look for --> sources/file.move:N after the error line
    let lines: Vec<&str> = raw.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if *line == error_line {
            // Check next few lines for file reference
            for j in i + 1..std::cmp::min(i + 5, lines.len()) {
                let l = lines[j].trim();
                if l.starts_with("-->") {
                    // --> sources/module.move:10:5
                    let parts: Vec<&str> = l.trim_start_matches("-->").trim().split(':').collect();
                    if !parts.is_empty() {
                        return parts[0].trim().to_string();
                    }
                }
            }
        }
    }
    "unknown".to_string()
}

fn extract_line_number(raw: &str, error_line: &str) -> Option<u32> {
    let lines: Vec<&str> = raw.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if *line == error_line {
            for j in i + 1..std::cmp::min(i + 5, lines.len()) {
                let l = lines[j].trim();
                if l.starts_with("-->") {
                    // --> sources/module.move:10:5
                    let parts: Vec<&str> = l.trim_start_matches("-->").trim().split(':').collect();
                    if parts.len() >= 2 {
                        return parts[1].trim().parse().ok();
                    }
                }
            }
        }
    }
    None
}

pub fn classify_error_string(msg: &str) -> String {
    let msg_lower = msg.to_lowercase();

    if msg_lower.contains("overflow") {
        "IntegerOverflow".to_string()
    } else if msg_lower.contains("signer") || msg_lower.contains("access") {
        "AccessControl".to_string()
    } else if msg_lower.contains("ability") || msg_lower.contains("capability") {
        "CapabilityLeak".to_string()
    } else if msg_lower.contains("abort") {
        "UnhandledAbort".to_string()
    } else if msg_lower.contains("type") || msg_lower.contains("mismatch") {
        "TypeSafety".to_string()
    } else if msg_lower.contains("undefined") || msg_lower.contains("unbound") {
        "MissingDefinition".to_string()
    } else if msg_lower.contains("unused") {
        "DeadCode".to_string()
    } else {
        "Unknown".to_string()
    }
}
