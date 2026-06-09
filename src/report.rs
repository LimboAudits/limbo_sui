use crate::types::{AuditResult, ConfidenceLevel, ExploitResult, Severity};
use anyhow::Result;
use chrono::Utc;
use colored::*;
use std::fs;
use std::path::Path;

pub fn write(result: &AuditResult, ai_content: &str, output_dir: &str) -> Result<String> {
    let filename = format!(
        "limbo.report.{}.md",
        result
            .contract_name
            .to_lowercase()
            .replace(' ', "_")
            .replace('/', "_")
    );
    let output_path = Path::new(output_dir).join(&filename);

    let report = build_report(result, ai_content);
    fs::write(&output_path, &report)?;

    println!(
        "\n  {} {}",
        "◆ Report saved:".white().bold(),
        output_path.display().to_string().cyan()
    );

    Ok(output_path.to_string_lossy().to_string())
}

fn build_report(result: &AuditResult, ai_content: &str) -> String {
    let date = Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();

    let risk_label = match result.risk_score {
        80..=100 => "🔴 CRITICAL",
        60..=79 => "🟠 HIGH",
        40..=59 => "🟡 MEDIUM",
        20..=39 => "🟢 LOW",
        _ => "⚪ MINIMAL",
    };

    let confirmed = result
        .findings
        .iter()
        .filter(|f| f.confidence == ConfidenceLevel::Confirmed)
        .count();

    let high_conf = result
        .findings
        .iter()
        .filter(|f| f.confidence == ConfidenceLevel::High)
        .count();

    let false_pos = result
        .findings
        .iter()
        .filter(|f| f.confidence == ConfidenceLevel::FalsePositive)
        .count();

    let proven = result
        .findings
        .iter()
        .filter(|f| {
            f.proof
                .as_ref()
                .map(|p| p.result == ExploitResult::Confirmed)
                .unwrap_or(false)
        })
        .count();

    format!(
        r#"# LIMBO
> Your contract won't leave the same.

---

**Protocol:** `{contract_name}`
**Network:** Sui
**Language:** Move
**Date:** {date}
**Audited by:** limbo_sui v0.2.0
**Duration:** {duration}s

---

## {risk_score} RISK SCORE / 100 — {risk_label}

| ✅ Confirmed | 🔬 Exploit Proven | 🔍 High Confidence | ❌ False Positives |
|:-----------:|:----------------:|:-----------------:|:-----------------:|
| {confirmed} | {proven} | {high_conf} | {false_pos} |

---

{ai_content}

---

## FINDING DETAILS

{findings_detail}

---

## CODEBASE SUMMARY

| Metric | Value |
|:-------|:------|
| Move files scanned | {file_count} |
| Entry points found | {entry_count} |
| Math operations analyzed | {math_count} |
| Transfer calls checked | {transfer_count} |
| Total lines | {total_lines} |

---

*Your contract has been to Limbo.*
*Powered by [Limbo](https://github.com/LimboAudits/limbo_sui) — Astrophel*
*CONFIDENTIAL — Limbo Security Audit*
"#,
        contract_name = result.contract_name,
        date = date,
        duration = result.duration_secs,
        risk_score = result.risk_score,
        risk_label = risk_label,
        confirmed = confirmed,
        proven = proven,
        high_conf = high_conf,
        false_pos = false_pos,
        ai_content = ai_content,
        findings_detail = format_findings_detail(result),
        file_count = result.recon.move_files.len(),
        entry_count = result.recon.entry_points.len(),
        math_count = result.recon.math_operations.len(),
        transfer_count = result.recon.transfer_calls.len(),
        total_lines = result.recon.total_lines,
    )
}

fn format_findings_detail(result: &AuditResult) -> String {
    if result.findings.is_empty() {
        return "No findings detected.".to_string();
    }

    result
        .findings
        .iter()
        .filter(|f| f.confidence != ConfidenceLevel::FalsePositive)
        .map(|f| {
            let confidence_badge = match f.confidence {
                ConfidenceLevel::Confirmed => "✅ CONFIRMED",
                ConfidenceLevel::High => "🔍 HIGH CONFIDENCE",
                ConfidenceLevel::Medium => "🔶 MEDIUM CONFIDENCE",
                ConfidenceLevel::FalsePositive => "❌ FALSE POSITIVE",
            };

            let proof_section = if let Some(proof) = &f.proof {
                format!(
                    "\n**Exploit Verification:** `{:?}` — {}\n```\n{}\n```",
                    proof.result,
                    proof.test_name,
                    proof.output.lines().take(5).collect::<Vec<_>>().join("\n")
                )
            } else {
                String::new()
            };

            format!(
                r#"### {} {} — {}
**ID:** `{}`
**Severity:** {} {}
**Confidence:** {}
**File:** `{}`
**Line:** {}
**CVE Class:** {}

**Code:**
```move
{}
```

**Description:** {}

**Exploit Scenario:** {}

**Recommendation:** {}
{}
---"#,
                f.severity.emoji(),
                f.id,
                f.title,
                f.id,
                f.severity.emoji(),
                f.severity.as_str(),
                confidence_badge,
                f.file,
                f.line.map_or("N/A".to_string(), |l| l.to_string()),
                f.cve_class,
                f.code_snippet,
                f.description,
                f.exploit_scenario,
                f.recommendation,
                proof_section,
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

pub fn print_terminal_summary(result: &AuditResult) {
    println!();
    println!("  {}", "─────────────────────────────────────".dimmed());
    println!(
        "  {} {}",
        "◆ AUDIT COMPLETE".white().bold(),
        result.contract_name.cyan().bold()
    );
    println!("  {}", "─────────────────────────────────────".dimmed());
    println!();

    let score_str = result.risk_score.to_string();
    let score_colored = match result.risk_score {
        80..=100 => score_str.red().bold(),
        60..=79 => score_str.yellow().bold(),
        40..=59 => score_str.yellow(),
        _ => score_str.green(),
    };

    println!("  {} {}/100", "Risk Score".dimmed(), score_colored);
    println!();

    // Show findings by severity
    let criticals: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.severity == Severity::Critical
                && f.confidence != ConfidenceLevel::FalsePositive
        })
        .collect();

    let highs: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.severity == Severity::High
                && f.confidence != ConfidenceLevel::FalsePositive
        })
        .collect();

    let mediums: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            f.severity == Severity::Medium
                && f.confidence != ConfidenceLevel::FalsePositive
        })
        .collect();

    if !criticals.is_empty() {
        println!("  {} {} critical", "🔴".normal(), criticals.len().to_string().red().bold());
        for f in &criticals {
            println!(
                "     {} {} — line {}",
                f.id.dimmed(),
                f.title.white(),
                f.line.unwrap_or(0).to_string().dimmed()
            );
        }
        println!();
    }

    if !highs.is_empty() {
        println!("  {} {} high", "🟠".normal(), highs.len().to_string().yellow().bold());
        for f in &highs {
            println!(
                "     {} {} — line {}",
                f.id.dimmed(),
                f.title.white(),
                f.line.unwrap_or(0).to_string().dimmed()
            );
        }
        println!();
    }

    if !mediums.is_empty() {
        println!("  {} {} medium", "🟡".normal(), mediums.len());
        println!();
    }

    let false_pos = result
        .findings
        .iter()
        .filter(|f| f.confidence == ConfidenceLevel::FalsePositive)
        .count();

    if false_pos > 0 {
        println!(
            "  {} {} false positive(s) filtered out by exploit engine",
            "✓".green(),
            false_pos
        );
        println!();
    }

    println!("  {}", "─────────────────────────────────────".dimmed());
    println!("  {}", "Your contract has been to Limbo.".dimmed().italic());
    println!();
}
