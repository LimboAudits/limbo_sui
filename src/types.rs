use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingStatus {
    Confirmed,      // L1/L2 + L3 agree
    HighConfidence, // L3 pattern only, strong match
    SingleTool,     // only one layer caught it
    FalsePositive,  // flagged but ruled out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub severity: Severity,
    pub status: FindingStatus,
    pub file: String,
    pub line: Option<u32>,
    pub description: String,
    pub raw_output: String,
    pub tools: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer1Result {
    pub success: bool,
    pub errors: Vec<BuildError>,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildError {
    pub file: String,
    pub line: Option<u32>,
    pub message: String,
    pub error_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer2Result {
    pub success: bool,
    pub failures: Vec<TestFailure>,
    pub total_tests: u32,
    pub passed: u32,
    pub failed: u32,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestFailure {
    pub test_name: String,
    pub module: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer3Result {
    pub confirmed: Vec<Finding>,
    pub potential: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResult {
    pub target: String,
    pub contract_name: String,
    pub layer1: Layer1Result,
    pub layer2: Layer2Result,
    pub layer3: Layer3Result,
    pub all_findings: Vec<Finding>,
    pub risk_score: u32,
    pub confirmed_count: usize,
    pub high_confidence_count: usize,
    pub single_tool_count: usize,
    pub false_positive_count: usize,
}
