/// On-chain submission module
/// Submits audit results to the Limbo Registry on Sui
/// Uses the sui CLI to call submit_audit

use crate::types::AuditResult;
use colored::*;
use std::process::Command;

pub fn submit(result: &AuditResult, registry_id: &str, package_id: &str) {
    println!("  {} Publishing audit to Sui...", "◆".cyan());

    let sui_bin = find_sui_binary();

    // Build the PTB call to submit_audit
    let output = Command::new(&sui_bin)
        .args([
            "client",
            "call",
            "--package", package_id,
            "--module", "registry",
            "--function", "submit_audit",
            "--args",
            registry_id,
            &format!("{}", result.contract_name),
            &format!("{}", result.target),
            &result.risk_score.to_string(),
            &result.confirmed_count.to_string(),
            &result.high_count.to_string(),
            &result.medium_count.to_string(),
            &result.false_positive_count.to_string(),
            "--gas-budget", "10000000",
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Extract transaction digest
            if let Some(digest) = extract_digest(&stdout) {
                println!(
                    "  {} Audit record published on Sui",
                    "✓".green().bold()
                );
                println!(
                    "  {} https://suiexplorer.com/txblock/{}",
                    "→".cyan(),
                    digest
                );
            } else {
                println!("  {} Audit published on-chain", "✓".green());
            }
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            println!(
                "  {} On-chain submission failed: {}",
                "!".yellow(),
                stderr.lines().next().unwrap_or("unknown error")
            );
            println!("  {} Run manually with: limbo_sui submit", "→".dimmed());
        }
        Err(e) => {
            println!(
                "  {} On-chain submission skipped: {}",
                "!".yellow(),
                e
            );
        }
    }
}

fn extract_digest(output: &str) -> Option<String> {
    // Look for "Transaction Digest: <hash>" in sui CLI output
    for line in output.lines() {
        if line.contains("Transaction Digest:") {
            return line
                .split(':')
                .nth(1)
                .map(|s| s.trim().to_string());
        }
    }
    None
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
