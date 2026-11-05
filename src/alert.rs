use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub timestamp: u64,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub source: String,
    pub target: String,
    pub description: String,
}

impl SecurityAlert {
    pub fn new(rule_id: &str, title: &str, severity: Severity, source: &str, target: &str, description: &str) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            timestamp: ts,
            rule_id: rule_id.to_string(),
            title: title.to_string(),
            severity,
            source: source.to_string(),
            target: target.to_string(),
            description: description.to_string(),
        }
    }
}
