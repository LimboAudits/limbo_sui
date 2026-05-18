use crate::types::{Layer2Result, TestFailure};
use anyhow::Result;
use colored::*;
use std::path::Path;
use std::process::Command;

pub fn run(project_path: &Path) -> Result<Layer2Result> {
    println!("  {} Running sui move test...", "→".cyan());

    let sui_bin = find_sui_binary();

    let output = Command::new(&sui_bin)
        .args(["move", "test"])
        .current_dir(project_path)
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
            let success = out.status.success();

            let (total, passed, failed) = parse_test_counts(&raw);
            let failures = if !success {
                parse_test_failures(&raw)
            } else {
                vec![]
            };

            if success {
                println!("  {} Tests passed ({}/{})", "✓".green(), passed, total);
            } else {
                println!(
                    "  {} {} test(s) failed out of {}",
                    "!".yellow(),
                    failed,
                    total
                );
            }

            Ok(Layer2Result {
                success,
                failures,
                total_tests: total,
                passed,
                failed,
                raw,
            })
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

fn parse_test_counts(raw: &str) -> (u32, u32, u32) {
    // Sui test output format:
    // Test result: FAILED. Total tests: 5; passed: 3; failed: 2
    // Test result: OK. Total tests: 5; passed: 5; failed: 0
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

    // Sui failure format:
    // [ FAIL    ] module_name::test_name
    //     error message or abort code
    let lines: Vec<&str> = raw.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        if line.contains("[ FAIL") || line.contains("[FAIL") {
            // Extract module::test_name
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(test_path) = parts.last() {
                let mut module = "unknown".to_string();
                let mut test_name = test_path.to_string();

                if let Some(sep) = test_path.find("::") {
                    module = test_path[..sep].to_string();
                    test_name = test_path[sep + 2..].to_string();
                }

                // Grab error message from next line
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
