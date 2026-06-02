use crate::layer1::find_move_packages;
use crate::types::{Layer2Result, TestFailure};
use anyhow::Result;
use colored::*;
use std::path::Path;
use std::process::Command;

pub fn run(project_path: &Path) -> Result<Layer2Result> {
    println!("  {} Running sui move test...", "→".cyan());

    let sui_bin = find_sui_binary();
    let packages = find_move_packages(project_path);

    if packages.is_empty() {
        println!("  {} No Move.toml found — skipping tests", "!".yellow());
        return Ok(Layer2Result {
            success: true,
            failures: vec![],
            total_tests: 0,
            passed: 0,
            failed: 0,
            raw: String::new(),
        });
    }

    let mut all_failures = Vec::new();
    let mut all_raw = String::new();
    let mut total = 0u32;
    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut overall_success = true;

    for package in &packages {
        let output = Command::new(&sui_bin)
            .args(["move", "test"])
            .current_dir(package)
            .output();

        match output {
            Err(_) => {
                println!("  {} sui binary not found, skipping tests", "!".yellow());
                return Ok(Layer2Result {
                    success: true,
                    failures: vec![],
                    total_tests: 0,
                    passed: 0,
                    failed: 0,
                    raw: String::new(),
                });
            }
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                let raw = format!("{}\n{}", stdout, stderr);
                all_raw.push_str(&raw);

                let (t, p, f) = parse_test_counts(&raw);
                total += t;
                passed += p;
                failed += f;

                if !out.status.success() {
                    overall_success = false;
                    let mut failures = parse_test_failures(&raw);
                    all_failures.append(&mut failures);
                    println!(
                        "  {} {} test(s) failed in {}",
                        "!".yellow(),
                        f,
                        package.file_name().unwrap_or_default().to_string_lossy()
                    );
                } else {
                    println!(
                        "  {} Tests passed ({}/{}) in {}",
                        "✓".green(),
                        p,
                        t,
                        package.file_name().unwrap_or_default().to_string_lossy()
                    );
                }
            }
        }
    }

    Ok(Layer2Result {
        success: overall_success,
        failures: all_failures,
        total_tests: total,
        passed,
        failed,
        raw: all_raw,
    })
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

fn parse_test_counts(raw: &str) -> (u32, u32, u32) {
    for line in raw.lines() {
        if line.contains("Test result") && line.contains("Total tests") {
            let total = extract_number(line, "Total tests:");
            let passed = extract_number(line, "passed:");
            let failed = extract_number(line, "failed:");
            return (total, passed, failed);
        }
    }
    (0, 0, 0)
}

fn extract_number(line: &str, prefix: &str) -> u32 {
    if let Some(pos) = line.find(prefix) {
        let rest = &line[pos + prefix.len()..];
        let num_str: String = rest
            .trim()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        return num_str.parse().unwrap_or(0);
    }
    0
}

fn parse_test_failures(raw: &str) -> Vec<TestFailure> {
    let mut failures = Vec::new();
    let lines: Vec<&str> = raw.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        if line.contains("[ FAIL") || line.contains("[FAIL") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(test_path) = parts.last() {
                let mut module = "unknown".to_string();
                let mut test_name = test_path.to_string();

                if let Some(sep) = test_path.find("::") {
                    module = test_path[..sep].to_string();
                    test_name = test_path[sep + 2..].to_string();
                }

                let message = if i + 1 < lines.len() {
                    lines[i + 1].trim().to_string()
                } else {
                    "Test failed".to_string()
                };

                failures.push(TestFailure {
                    test_name,
                    module,
                    message,
                });
            }
        }
    }
    failures
}
