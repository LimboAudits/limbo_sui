use crate::types::{AuditResult, FindingStatus, Severity};
use anyhow::Result;
use chrono::Utc;
use colored::*;
use std::fs;
use std::path::Path;

pub fn write(result: &AuditResult, ai_content: &str, output_dir: &str) -> Result<String> {
    let filename = format!(
        "limbo.report.{}.md",
        result.contract_name.to_lowercase().replace(' ', "_")
    );
    let output_path = Path::new(output_dir).join(&filename);

    let report = build_report(result, ai_content);

    fs::write(&output_path, &report)?;

    println!(
        "\n  {} Report written: {}",
        "✓".green().bold(),
        output_path.display().to_string().white().bold()
    );

    Ok(output_path.to_string_lossy().to_string())
}

fn build_report(result: &AuditResult, ai_content: &str) -> String {
    let date = Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();

    let severity_badge = match result.risk_score {
        80..=100 => "🔴 CRITICAL",
        60..=79 => "🟠 HIGH",
        40..=59 => "🟡 MEDIUM",
        20..=39 => "🟢 LOW",
        _ => "⚪ MINIMAL",
    };

    format!(
        r#"# LIMBO
> Your contract won't leave the same.

---

**Protocol:** `{contract_name}`  
**Network:** Sui  
**Language:** Move  
**Date:** {date}  
**Audited by:** limbo_sui v0.1.0  

---

## {risk_score} RISK SCORE / 100 — {severity_badge}

| ✅ Confirmed | 🔍 High Confidence | 🔧 Single Tool | ❌ False Positives |
|:-----------:|:-----------------:|:-------------:|:-----------------:|
| {confirmed} | {high_conf} | {single_tool} | {false_pos} |

---

{ai_content}

---

## RAW FINDINGS REFERENCE

### Layer 1 — Build Analysis
```
{l1_raw}
```

### Layer 2 — Test Analysis
```
{l2_raw}
```

---

*Your contract has been to Limbo.*  
*Powered by [Limbo](https://github.com/astrophel/limbo_sui) — Astrophel*  
*CONFIDENTIAL — Limbo Security Audit*
"#,
        contract_name = result.contract_name,
        date = date,
        risk_score = result.risk_score,
        severity_badge = severity_badge,
        confirmed = result.confirmed_count,
        high_conf = result.high_confidence_count,
        single_tool = result.single_tool_count,
        false_pos = result.false_positive_count,
        ai_content = ai_content,
        l1_raw = truncate(&result.layer1.raw, 2000),
        l2_raw = truncate(&result.layer2.raw, 2000),
    )
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}

/// Print a summary to terminal after audit completes
pub fn print_terminal_summary(result: &AuditResult) {
    println!();
    println!("{}", "  ─────────────────────────────────────".dimmed());
    println!("  {} {}", "AUDIT COMPLETE".white().bold(), result.contract_name.cyan().bold());
    println!("{}", "  ─────────────────────────────────────".dimmed());
    println!();

    // Risk score with color
    let score_colored = match result.risk_score {
        80..=100 => result.risk_score.to_string().red().bold(),
        60..=79 => result.risk_score.to_string().yellow().bold(),
        _ => result.risk_score.to_string().green().bold(),
    };
    println!("  Risk Score:     {}/100", score_colored);
    println!();

    // Findings table
    println!("  Confirmed:      {}", result.confirmed_count.to_string().red().bold());
    println!("  High Conf:      {}", result.high_confidence_count.to_string().yellow());
    println!("  Single Tool:    {}", result.single_tool_count.to_string().blue());
    println!("  False Pos:      {}", result.false_positive_count.to_string().dimmed());
    println!();

    // List confirmed findings
    if !result.layer3.confirmed.is_empty() {
        println!("  {}", "CONFIRMED VULNERABILITIES:".red().bold());
        for f in &result.layer3.confirmed {
            let sev = match f.severity {
                Severity::Critical => "[CRITICAL]".red().bold(),
                Severity::High => "[HIGH]    ".yellow().bold(),
                Severity::Medium => "[MEDIUM]  ".blue(),
                _ => "[LOW]     ".dimmed(),
            };
            println!("  {} {} — line {:?}", sev, f.title.white(), f.line);
        }
        println!();
    }

    println!("{}", "  ─────────────────────────────────────".dimmed());
    println!(
        "  {}",
        "Your contract has been to Limbo.".dimmed().italic()
    );
    println!();
}
