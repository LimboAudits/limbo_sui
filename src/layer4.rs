use crate::types::{AuditResult, Finding};
use anyhow::{Context, Result};
use colored::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct GeminiRequest {
    contents: Vec<GeminiContent>,
    #[serde(rename = "generationConfig")]
    generation_config: GenerationConfig,
}

#[derive(Serialize, Deserialize)]
struct GeminiContent {
    parts: Vec<GeminiPart>,
}

#[derive(Serialize, Deserialize)]
struct GeminiPart {
    text: String,
}

#[derive(Serialize, Deserialize)]
struct GenerationConfig {
    temperature: f32,
    #[serde(rename = "maxOutputTokens")]
    max_output_tokens: u32,
}

#[derive(Deserialize)]
struct GeminiResponse {
    candidates: Vec<GeminiCandidate>,
}

#[derive(Deserialize)]
struct GeminiCandidate {
    content: GeminiContent,
}

pub async fn generate_report(result: &AuditResult) -> Result<String> {
    println!("  {} Generating AI report...", "→".cyan());

    let api_key = std::env::var("GEMINI_API_KEY")
        .context("GEMINI_API_KEY not set. Add it to .env or export it.")?;

    let prompt = build_prompt(result);

    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={}",
        api_key
    );

    let request_body = GeminiRequest {
        contents: vec![GeminiContent {
            parts: vec![GeminiPart { text: prompt }],
        }],
        generation_config: GenerationConfig {
            temperature: 0.2, // Low temp = consistent, professional output
            max_output_tokens: 4096,
        },
    };

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&request_body)
        .timeout(std::time::Duration::from_secs(30)).send()
        .await
        .context("Failed to reach Gemini API")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Gemini API error {}: {}", status, body);
    }

    let gemini_response: GeminiResponse = response
        .json()
        .await
        .context("Failed to parse Gemini response")?;

    let text = gemini_response
        .candidates
        .first()
        .and_then(|c| c.content.parts.first())
        .map(|p| p.text.clone())
        .unwrap_or_else(|| "Report generation failed.".to_string());

    println!("  {} AI report generated", "✓".green());
    Ok(text)
}

fn build_prompt(result: &AuditResult) -> String {
    let confirmed_str = format_findings_for_prompt(&result.layer3.confirmed);
    let potential_str = format_findings_for_prompt(&result.layer3.potential);

    let unknown_errors: Vec<String> = result
        .layer1
        .errors
        .iter()
        .filter(|e| e.error_type == "Unknown")
        .map(|e| format!("- {} ({})", e.message, e.file))
        .collect();

    let unknown_str = if unknown_errors.is_empty() {
        "None".to_string()
    } else {
        unknown_errors.join("\n")
    };

    let l1_summary = if result.layer1.success {
        "Build passed with no errors.".to_string()
    } else {
        format!(
            "Build failed with {} error(s):\n{}",
            result.layer1.errors.len(),
            result
                .layer1
                .errors
                .iter()
                .map(|e| format!("  - [{}] {} ({}:{})",
                    e.error_type,
                    e.message,
                    e.file,
                    e.line.map_or("?".to_string(), |l| l.to_string())
                ))
                .collect::<Vec<_>>()
                .join("\n")
        )
    };

    let l2_summary = if result.layer2.success {
        format!(
            "All {} tests passed.",
            result.layer2.total_tests
        )
    } else {
        format!(
            "{}/{} tests failed:\n{}",
            result.layer2.failed,
            result.layer2.total_tests,
            result
                .layer2
                .failures
                .iter()
                .map(|f| format!("  - {}::{}: {}", f.module, f.test_name, f.message))
                .collect::<Vec<_>>()
                .join("\n")
        )
    };

    format!(
        r#"You are a senior Move smart contract security auditor working for Limbo Security.

Analyze the following audit findings and generate a professional security report.

CONTRACT: {contract_name}
NETWORK: Sui
RISK SCORE: {risk_score}/100
DATE: {date}

═══════════════════════════════
LAYER 1 — BUILD ANALYSIS
═══════════════════════════════
{l1_summary}

═══════════════════════════════
LAYER 2 — TEST ANALYSIS  
═══════════════════════════════
{l2_summary}

═══════════════════════════════
LAYER 3 — CONFIRMED FINDINGS
═══════════════════════════════
{confirmed}

═══════════════════════════════
LAYER 3 — POTENTIAL FINDINGS
═══════════════════════════════
{potential}

═══════════════════════════════
UNCLASSIFIED ERRORS (classify these)
═══════════════════════════════
{unknown}

═══════════════════════════════
INSTRUCTIONS
═══════════════════════════════
Generate a professional Markdown security audit report with EXACTLY this structure:

## EXECUTIVE SUMMARY
[2-3 paragraphs. Describe the contract purpose, overall security posture, most critical risks, and immediate recommended actions. Be specific about what the contract does and what the worst case exploit scenario is.]

## CONFIRMED FINDINGS
[For each confirmed finding:]
### [SEVERITY] — [Title]
**File:** [file path]  
**Line:** [line number]  
**Tools:** [which tools detected it]  
**Description:** [plain English explanation]  
**Exploit Scenario:** [step by step how an attacker exploits this]  
**Recommendation:** [specific fix with code example if possible]

---

## HIGH CONFIDENCE FINDINGS
[Same format as above for potential findings]

---

## UNCLASSIFIED ERRORS
[For each unknown error, identify what type of vulnerability it is, severity, and explanation]

---

## RISK ASSESSMENT
[Brief table or summary of overall risk distribution]

Be direct, specific, and technical. Do not add preamble or postamble. Start directly with ## EXECUTIVE SUMMARY."#,
        contract_name = result.contract_name,
        risk_score = result.risk_score,
        date = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC"),
        l1_summary = l1_summary,
        l2_summary = l2_summary,
        confirmed = if confirmed_str.is_empty() { "None detected.".to_string() } else { confirmed_str },
        potential = if potential_str.is_empty() { "None detected.".to_string() } else { potential_str },
        unknown = unknown_str,
    )
}

fn format_findings_for_prompt(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return String::new();
    }

    findings
        .iter()
        .map(|f| {
            format!(
                "• [{}] {} — {} (line {:?})\n  {}",
                f.severity.as_str(),
                f.title,
                f.file,
                f.line,
                f.description
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}
