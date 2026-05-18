use crate::{classifier, git, layer1, layer2, layer3, layer4, report};
use crate::types::{AuditResult, Finding, FindingStatus};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

pub async fn run(target: String, output: String) {
    println!("  {} Target: {}", "→".cyan(), target.white().bold());
    println!();

    // ── Resolve target ─────────────────────────────────────────────────────
    let resolved = match git::resolve(&target).await {
        Ok(r) => r,
        Err(e) => {
            println!("  {} {}", "✗".red().bold(), e);
            return;
        }
    };

    let project_path = &resolved.path;
    let contract_name = resolved.name.clone();

    // ── Collect .move files ────────────────────────────────────────────────
    let move_files = git::collect_move_files(project_path);
    println!(
        "  {} Found {} .move file(s)\n",
        "→".cyan(),
        move_files.len()
    );

    if move_files.is_empty() {
        println!("  {} No Move files found in target.", "✗".red());
        return;
    }

    // ── Layer 1: sui move build ────────────────────────────────────────────
    let l1 = match layer1::run(project_path) {
        Ok(r) => r,
        Err(e) => {
            println!("  {} Layer 1 error: {}", "✗".red(), e);
            return;
        }
    };

    // ── Layer 2: sui move test ─────────────────────────────────────────────
    let l2 = match layer2::run(project_path) {
        Ok(r) => r,
        Err(e) => {
            println!("  {} Layer 2 error: {}", "✗".red(), e);
            return;
        }
    };

    // ── Layer 3: pattern scanner ───────────────────────────────────────────
    let l3 = layer3::run(&move_files, &l1, &l2);

    // ── Classifier: map remaining L1/L2 errors ─────────────────────────────
    let classified = classifier::classify(&l1, &l2);

    // ── Combine all findings ───────────────────────────────────────────────
    let mut all_findings: Vec<Finding> = Vec::new();
    all_findings.extend(l3.confirmed.clone());
    all_findings.extend(l3.potential.clone());
    all_findings.extend(classified);

    // Deduplicate by title + file
    all_findings.dedup_by(|a, b| a.title == b.title && a.file == b.file);

    // ── Calculate risk score ───────────────────────────────────────────────
    let risk_score = calculate_risk_score(&all_findings);

    let confirmed_count = all_findings
        .iter()
        .filter(|f| matches!(f.status, FindingStatus::Confirmed))
        .count();

    let high_confidence_count = all_findings
        .iter()
        .filter(|f| matches!(f.status, FindingStatus::HighConfidence))
        .count();

    let single_tool_count = all_findings
        .iter()
        .filter(|f| matches!(f.status, FindingStatus::SingleTool))
        .count();

    let false_positive_count = all_findings
        .iter()
        .filter(|f| matches!(f.status, FindingStatus::FalsePositive))
        .count();

    let audit_result = AuditResult {
        target: target.clone(),
        contract_name: contract_name.clone(),
        layer1: l1,
        layer2: l2,
        layer3: l3,
        all_findings,
        risk_score,
        confirmed_count,
        high_confidence_count,
        single_tool_count,
        false_positive_count,
    };

    // ── Print terminal summary ─────────────────────────────────────────────
    report::print_terminal_summary(&audit_result);

    // ── Layer 4: AI report generation ─────────────────────────────────────
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
        Ok(path) => {
            println!("  {} {}", "→".cyan(), path.white());
        }
        Err(e) => {
            println!("  {} Failed to write report: {}", "✗".red(), e);
        }
    }

    // ── Cleanup temp clone ─────────────────────────────────────────────────
    if resolved.is_temp {
        let _ = std::fs::remove_dir_all(&resolved.path);
    }
}

fn calculate_risk_score(findings: &[Finding]) -> u32 {
    use crate::types::Severity;

    let raw: u32 = findings
        .iter()
        .filter(|f| !matches!(f.status, FindingStatus::FalsePositive))
        .map(|f| f.severity.score())
        .sum();

    // Cap at 100
    std::cmp::min(raw, 100)
}

fn generate_fallback_report(result: &AuditResult) -> String {
    // If Gemini API fails, generate a basic structured report without AI
    let mut sections = Vec::new();

    sections.push("## EXECUTIVE SUMMARY\n".to_string());
    sections.push(format!(
        "Automated security analysis of `{}` completed. \
        Found {} total issue(s) requiring attention. \
        Risk score: {}/100.\n",
        result.contract_name, result.all_findings.len(), result.risk_score
    ));

    if !result.layer3.confirmed.is_empty() {
        sections.push("\n## CONFIRMED FINDINGS\n".to_string());
        for f in &result.layer3.confirmed {
            sections.push(format!(
                "\n### [{}] — {}\n**File:** {}  \n**Line:** {:?}  \n**Description:** {}\n",
                f.severity.as_str(),
                f.title,
                f.file,
                f.line,
                f.description
            ));
        }
    }

    if !result.layer3.potential.is_empty() {
        sections.push("\n## HIGH CONFIDENCE FINDINGS\n".to_string());
        for f in &result.layer3.potential {
            sections.push(format!(
                "\n### [{}] — {}\n**File:** {}  \n**Line:** {:?}  \n**Description:** {}\n",
                f.severity.as_str(),
                f.title,
                f.file,
                f.line,
                f.description
            ));
        }
    }

    sections.push(
        "\n> *AI report generation unavailable. Set GEMINI_API_KEY for full analysis.*\n"
            .to_string(),
    );

    sections.join("")
}
