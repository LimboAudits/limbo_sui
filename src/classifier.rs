use crate::types::{Finding, FindingStatus, Layer1Result, Layer2Result, Severity};
use colored::*;

/// Takes Layer 1 + Layer 2 raw output and classifies any findings
/// that Layer 3 didn't already catch — using pattern matching first,
/// then flagging unknowns for the AI layer.
pub fn classify(layer1: &Layer1Result, layer2: &Layer2Result) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Classify Layer 1 build errors
    for error in &layer1.errors {
        if error.error_type == "Unknown" || error.error_type == "MissingTool" {
            continue; // Let AI handle these
        }

        let (severity, description) = map_error_type(&error.error_type, &error.message);

        findings.push(Finding {
            title: format!("Build Error: {}", error.error_type),
            severity,
            status: FindingStatus::SingleTool,
            file: error.file.clone(),
            line: error.line,
            description,
            raw_output: error.message.clone(),
            tools: vec!["sui_move_build".to_string()],
        });
    }

    // Classify Layer 2 test failures
    for failure in &layer2.failures {
        let (severity, description) = classify_test_failure(&failure.message);

        findings.push(Finding {
            title: format!("Test Failure: {}", failure.test_name),
            severity,
            status: FindingStatus::SingleTool,
            file: format!("{}.move", failure.module),
            line: None,
            description,
            raw_output: failure.message.clone(),
            tools: vec!["sui_move_test".to_string()],
        });
    }

    if !findings.is_empty() {
        println!(
            "  {} Classifier: {} additional finding(s)",
            "→".cyan(),
            findings.len()
        );
    }

    findings
}

fn map_error_type(error_type: &str, raw: &str) -> (Severity, String) {
    match error_type {
        "IntegerOverflow" => (
            Severity::High,
            format!(
                "Integer overflow detected in build output. \
                Unchecked arithmetic on integer types can allow attackers to \
                manipulate values past their maximum, leading to fund loss or \
                logic bypass. Raw: {}",
                raw
            ),
        ),
        "AccessControl" => (
            Severity::Critical,
            format!(
                "Access control issue detected. Missing signer/capability \
                check allows unauthorized callers to invoke privileged functions. \
                Raw: {}",
                raw
            ),
        ),
        "CapabilityLeak" => (
            Severity::High,
            format!(
                "Capability object leaked or improperly handled. \
                Capabilities grant elevated permissions — leaking them \
                allows privilege escalation. Raw: {}",
                raw
            ),
        ),
        "UnhandledAbort" => (
            Severity::Medium,
            format!(
                "Unhandled abort condition. The contract may abort \
                unexpectedly, causing transaction failures or denial of service. \
                Raw: {}",
                raw
            ),
        ),
        "TypeSafety" => (
            Severity::Medium,
            format!(
                "Type safety violation. Incorrect type usage can lead to \
                unexpected behavior or exploitable conditions. Raw: {}",
                raw
            ),
        ),
        "MissingDefinition" => (
            Severity::Low,
            format!(
                "Undefined reference in contract. This may indicate \
                incomplete implementation or missing dependency. Raw: {}",
                raw
            ),
        ),
        "DeadCode" => (
            Severity::Low,
            format!(
                "Dead or unused code detected. While not directly exploitable, \
                dead code can indicate incomplete security controls. Raw: {}",
                raw
            ),
        ),
        _ => (
            Severity::Info,
            format!("Build issue detected. Raw: {}", raw),
        ),
    }
}

fn classify_test_failure(message: &str) -> (Severity, String) {
    let msg_lower = message.to_lowercase();

    if msg_lower.contains("abort") && msg_lower.contains("arithmetic") {
        (
            Severity::High,
            format!(
                "Test failed with arithmetic abort — potential integer overflow \
                or underflow in contract logic. Message: {}",
                message
            ),
        )
    } else if msg_lower.contains("abort") {
        (
            Severity::Medium,
            format!(
                "Test aborted unexpectedly. This may indicate missing bounds \
                checks or invalid state transitions. Message: {}",
                message
            ),
        )
    } else if msg_lower.contains("unauthorized") || msg_lower.contains("permission") {
        (
            Severity::High,
            format!(
                "Test failed due to authorization error — access control \
                may be incorrectly implemented. Message: {}",
                message
            ),
        )
    } else {
        (
            Severity::Low,
            format!("Test failure detected. Message: {}", message),
        )
    }
}

/// Returns findings that couldn't be classified — to be sent to AI
pub fn get_unknown_errors(layer1: &Layer1Result) -> Vec<String> {
    layer1
        .errors
        .iter()
        .filter(|e| e.error_type == "Unknown")
        .map(|e| e.message.clone())
        .collect()
}
