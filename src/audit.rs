use crate::{exploit, git, layer1, layer3, layer4, report};
use crate::types::{AuditResult, ConfidenceLevel, Severity};
use colored::*;
use std::time::Instant;

pub async fn run(target: String, output: String, no_exploit: bool) {
    let start = Instant::now();

    println!("  {} {}", "target".dimmed(), target.white().bold());
    println!();

    // ── Resolve target ─────────────────────────────────────────────────────
    let resolved = match git::resolve(&target).await {
        Ok(r) => r,
        Err(e) => {
            println!("  {} {}", "✗ failed:".red(), e);
            return;
        }
    };

    let project_path = &resolved.path;
    let contract_name = resolved.name.clone();

    // ── Collect .move files ────────────────────────────────────────────────
    let move_files = git::collect_move_files(project_path);

    if move_files.is_empty() {
        println!("  {} No Move files found", "✗".red());
        return;
    }

    println!(
        "  {} {} Move file(s) found",
        "◆".cyan(),
        move_files.len()
    );
    println!();

    // ── Layer 1: RECON ─────────────────────────────────────────────────────
    let recon = layer1::run(&move_files, &contract_name);
    println!();

    // ── Layer 3: PATTERN SCANNER ───────────────────────────────────────────
    let mut findings = layer3::run(&move_files, &recon);
    println!();

    // ── Layer 2: EXPLOIT ENGINE ────────────────────────────────────────────
    if !no_exploit && !findings.is_empty() {
        exploit::verify_findings(&mut findings, &move_files, project_path).await;
        println!();
    } else if no_exploit {
        println!("  {} Exploit verification skipped (--no-exploit)", "!".yellow());
        println!();
    }

    // ── Calculate risk score ───────────────────────────────────────────────
    let risk_score = calculate_risk_score(&findings);

    let confirmed_count = findings
        .iter()
        .filter(|f| f.confidence == ConfidenceLevel::Confirmed)
        .count();

    let high_count = findings
        .iter()
        .filter(|f| f.confidence == ConfidenceLevel::High)
        .count();

    let medium_count = findings
        .iter()
        .filter(|f| f.confidence == ConfidenceLevel::Medium)
        .count();

    let false_positive_count = findings
        .iter()
        .filter(|f| f.confidence == ConfidenceLevel::FalsePositive)
        .count();

    let duration_secs = start.elapsed().as_secs();

    let audit_result = AuditResult {
        target: target.clone(),
        contract_name: contract_name.clone(),
        recon,
        findings,
        risk_score,
        confirmed_count,
        high_count,
        medium_count,
        false_positive_count,
        duration_secs,
    };

    // ── Print terminal summary ─────────────────────────────────────────────
    report::print_terminal_summary(&audit_result);

    // ── Layer 4: AI REPORT ─────────────────────────────────────────────────
    let ai_content = match layer4::generate_report(&audit_result).await {
        Ok(content) => content,
        Err(e) => {
            println!(
                "  {} AI report skipped: {} — writing basic report",
                "!".yellow(),
                e
            );
            generate_fallback_report(&audit_result)
        }
    };

    // ── Write report ───────────────────────────────────────────────────────
    match report::write(&audit_result, &ai_content, &output) {
        Ok(_) => {}
        Err(e) => {
            println!("  {} Failed to write report: {}", "✗".red(), e);
        }
    }

    // ── Cleanup ────────────────────────────────────────────────────────────
    if resolved.is_temp {
        let _ = std::fs::remove_dir_all(&resolved.path);
    }
}

fn calculate_risk_score(findings: &[crate::types::Finding]) -> u32 {
    let raw: u32 = findings
        .iter()
        .filter(|f| f.confidence != ConfidenceLevel::FalsePositive)
        .map(|f| f.severity.score())
        .sum();

    std::cmp::min(raw, 100)
}

fn generate_fallback_report(result: &AuditResult) -> String {
    let mut sections = Vec::new();

    sections.push("## EXECUTIVE SUMMARY\n".to_string());
    sections.push(format!(
        "Automated security analysis of `{}` completed. Found {} finding(s). Risk score: {}/100.\n",
        result.contract_name,
        result.findings.iter().filter(|f| f.confidence != ConfidenceLevel::FalsePositive).count(),
        result.risk_score
    ));

    let real_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.confidence != ConfidenceLevel::FalsePositive)
        .collect();

    if !real_findings.is_empty() {
        sections.push("\n## FINDINGS\n".to_string());
        for f in &real_findings {
            sections.push(format!(
                "\n### {} {} — {}\n**File:** `{}`\n**Line:** {}\n\n{}\n\n**Fix:** {}\n",
                f.severity.emoji(),
                f.id,
                f.title,
                f.file,
                f.line.unwrap_or(0),
                f.description,
                f.recommendation
            ));
        }
    }

    sections.push(
        "\n> *AI report generation unavailable. Set GEMINI_API_KEY for full analysis.*\n"
            .to_string(),
    );

    sections.join("")
}
