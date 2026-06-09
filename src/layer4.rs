/// Layer 4: AI EXPLAINER
/// Only receives CONFIRMED findings from Layer 2 + 3
/// Zero hallucinations — explains real findings, never invents
/// Gemini 2.5 Flash with retry logic

use crate::types::{AuditResult, ConfidenceLevel, Finding};
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
    println!("  {} Generating AI report...", "◆".cyan());

    let api_key = std::env::var("GEMINI_API_KEY")
        .context("GEMINI_API_KEY not set. Get a free key at aistudio.google.com")?;

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
            temperature: 0.1, // Very low = consistent, professional, no creativity
            max_output_tokens: 4096,
        },
    };

    let client = reqwest::Client::new();

    for attempt in 1..=3 {
        let response = client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .timeout(std::time::Duration::from_secs(45))
            .send()
            .await
            .context("Failed to reach Gemini API")?;

        let status = response.status();

        if status.as_u16() == 503 || status.as_u16() == 429 {
            if attempt < 3 {
                println!(
                    "  {} Gemini busy, retrying ({}/3)...",
                    "!".yellow(),
                    attempt
                );
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            } else {
                anyhow::bail!("Gemini unavailable after 3 attempts");
            }
        }

        if !status.is_success() {
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
        return Ok(text);
    }

    anyhow::bail!("Gemini unavailable after 3 attempts")
}

fn build_prompt(result: &AuditResult) -> String {
    // Only send confirmed and high confidence findings to AI
    // Never send false positives
    let real_findings: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|f| {
            f.confidence != ConfidenceLevel::FalsePositive
        })
        .take(10) // Limit to avoid token overflow
        .collect();

    let findings_text = real_findings
        .iter()
        .map(|f| {
            format!(
                r#"
ID: {}
Title: {}
Severity: {}
Confidence: {:?}
File: {}
Line: {}
Code: {}
CVE Class: {}
Description: {}
---"#,
                f.id,
                f.title,
                f.severity.as_str(),
                f.confidence,
                f.file,
                f.line.unwrap_or(0),
                f.code_snippet,
                f.cve_class,
                f.description,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let proof_summary = real_findings
        .iter()
        .filter(|f| f.proof.is_some())
        .map(|f| {
            let proof = f.proof.as_ref().unwrap();
            format!("- {} ({:?}): {:?}", f.id, f.confidence, proof.result)
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"You are a senior Move smart contract security auditor for Limbo Security.

IMPORTANT: You are NOT finding new bugs. You are explaining bugs that have already been CONFIRMED by static analysis and exploit testing. Do not hallucinate or invent findings. Only explain what is listed below.

CONTRACT: {}
NETWORK: Sui
RISK SCORE: {}/100
TOTAL FINDINGS: {}
DATE: {}

CONFIRMED FINDINGS (already verified by limbo_sui):
{}

EXPLOIT VERIFICATION RESULTS:
{}

Your task: Generate a professional security audit report in Markdown.

Rules:
1. Only discuss findings listed above
2. Do not invent additional findings
3. Be specific about file paths and line numbers
4. Reference real Sui/Move vulnerabilities (Cetus hack, capability misuse, etc.)
5. Give concrete code fixes

Use EXACTLY this structure:

## EXECUTIVE SUMMARY
[2-3 paragraphs: contract purpose, overall risk, worst case scenario, immediate actions needed]

## FINDINGS

[For each finding, use this format:]
### {} [ID] — [Title]
**Severity:** [CRITICAL/HIGH/MEDIUM/LOW]
**Confidence:** [Confirmed/High/Medium]
**File:** `[path]`
**Line:** [number]
**Code:** `[snippet]`

**What's wrong:**
[Clear explanation of the vulnerability]

**How an attacker exploits this:**
[Step by step attack scenario]

**Fix:**
```move
[concrete code fix]
```

---

## RISK SUMMARY
| Severity | Count |
|:---------|:------|
| CRITICAL | [n] |
| HIGH | [n] |
| MEDIUM | [n] |
| LOW | [n] |

Start directly with ## EXECUTIVE SUMMARY. No preamble."#,
        result.contract_name,
        result.risk_score,
        real_findings.len(),
        chrono::Utc::now().format("%Y-%m-%d %H:%M UTC"),
        findings_text,
        if proof_summary.is_empty() {
            "No exploit tests run (sui binary not available)".to_string()
        } else {
            proof_summary
        },
        "🔴", // severity emoji placeholder
    )
}
