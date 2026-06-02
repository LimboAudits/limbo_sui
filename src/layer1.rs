use crate::types::{BuildError, Layer1Result};
use anyhow::Result;
use colored::*;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn run(project_path: &Path) -> Result<Layer1Result> {
    println!("  {} Running sui move build...", "→".cyan());

    let sui_bin = find_sui_binary();
    let packages = find_move_packages(project_path);

    if packages.is_empty() {
        println!("  {} No Move.toml found — skipping build", "!".yellow());
        return Ok(Layer1Result {
            success: true,
            errors: vec![],
            raw: String::new(),
        });
    }

    println!("  {} Found {} Move package(s)", "→".cyan(), packages.len());

    let mut all_errors = Vec::new();
    let mut all_raw = String::new();
    let mut overall_success = true;

    for package in &packages {
        let output = Command::new(&sui_bin)
            .args(["move", "build"])
            .current_dir(package)
            .output();

        match output {
            Err(e) => {
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
                all_raw.push_str(&raw);

                if !out.status.success() {
                    overall_success = false;
                    let mut errors = parse_build_errors(&raw);
                    all_errors.append(&mut errors);
                    println!(
                        "  {} Build failed in {}",
                        "!".yellow(),
                        package.display()
                    );
                } else {
                    println!(
                        "  {} Build passed: {}",
                        "✓".green(),
                        package.file_name().unwrap_or_default().to_string_lossy()
                    );
                }
            }
        }
    }

    if overall_success {
        println!("  {} All packages built successfully", "✓".green());
    } else {
        println!("  {} Found {} build error(s)", "→".cyan(), all_errors.len());
    }

    Ok(Layer1Result {
        success: overall_success,
        errors: all_errors,
        raw: all_raw,
    })
}

pub fn find_move_packages(dir: &Path) -> Vec<PathBuf> {
    let mut packages = Vec::new();
    find_packages_recursive(dir, &mut packages);
    // If none found in subdirs, try root
    if packages.is_empty() && dir.join("Move.toml").exists() {
        packages.push(dir.to_path_buf());
    }
    packages
}

fn find_packages_recursive(dir: &Path, packages: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if !name.starts_with('.') && name != "build" && name != "target" {
                    if path.join("Move.toml").exists() {
                        packages.push(path.clone());
                    }
                    find_packages_recursive(&path, packages);
                }
            }
        }
    }
}

fn find_sui_binary() -> String {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()));

    if let Some(dir) = exe_dir {
        let bundled = dir.join("bin").join("sui");
        if bundled.exists() {
            return bundled.to_string_lossy().to_string();
        }
    }
    "sui".to_string()
}

fn parse_build_errors(raw: &str) -> Vec<BuildError> {
    let mut errors = Vec::new();

    for line in raw.lines() {
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

    errors.dedup_by(|a, b| a.message == b.message);
    errors
}

fn extract_file_from_context(raw: &str, error_line: &str) -> String {
    let lines: Vec<&str> = raw.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if *line == error_line {
            for j in i + 1..std::cmp::min(i + 5, lines.len()) {
                let l = lines[j].trim();
                if l.starts_with("-->") {
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
