use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    pub fn score(&self) -> u32 {
        match self {
            Severity::Critical => 40,
            Severity::High => 25,
            Severity::Medium => 15,
            Severity::Low => 5,
            Severity::Info => 1,
        }
    }

    pub fn emoji(&self) -> &str {
        match self {
            Severity::Critical => "🔴",
            Severity::High => "🟠",
            Severity::Medium => "🟡",
            Severity::Low => "🟢",
            Severity::Info => "⚪",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConfidenceLevel {
    Confirmed,      // Layer 2 exploit ran and proved it
    High,           // Strong pattern match
    Medium,         // Pattern match, needs review
    FalsePositive,  // Exploit ran and disproved it
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: ConfidenceLevel,
    pub file: String,
    pub line: Option<u32>,
    pub code_snippet: String,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
    pub cve_class: String, // e.g. "Integer Overflow", "Cetus-Pattern"
    pub proof: Option<ExploitProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitProof {
    pub test_name: String,
    pub result: ExploitResult,
    pub output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExploitResult {
    Confirmed,   // exploit test passed = bug is real
    Refuted,     // exploit test failed = false positive
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconResult {
    pub contract_name: String,
    pub move_files: Vec<String>,
    pub entry_points: Vec<EntryPoint>,
    pub capabilities: Vec<String>,
    pub math_operations: Vec<MathOp>,
    pub transfer_calls: Vec<TransferCall>,
    pub total_lines: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPoint {
    pub name: String,
    pub file: String,
    pub line: u32,
    pub is_public: bool,
    pub params: String,
    pub has_ctx: bool,
    pub has_cap: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MathOp {
    pub file: String,
    pub line: u32,
    pub operation: String,
    pub operand_type: String,
    pub has_overflow_check: bool,
    pub is_bit_shift: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferCall {
    pub file: String,
    pub line: u32,
    pub call_type: String, // transfer, public_transfer
    pub has_ownership_check: bool,
    pub in_init: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResult {
    pub target: String,
    pub contract_name: String,
    pub recon: ReconResult,
    pub findings: Vec<Finding>,
    pub risk_score: u32,
    pub confirmed_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub false_positive_count: usize,
    pub duration_secs: u64,
}
