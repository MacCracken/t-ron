//! Security gate — core types for tool call checking.

use serde::{Deserialize, Serialize};

/// A tool call to be security-checked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub agent_id: String,
    pub tool_name: String,
    pub params: serde_json::Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Security verdict for a tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Verdict {
    Allow,
    Deny { reason: String, code: DenyCode },
    Flag { reason: String },
}

impl Verdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow | Self::Flag { .. })
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

/// Reason code for denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenyCode {
    Unauthorized,
    RateLimited,
    InjectionDetected,
    ToolDisabled,
    AnomalyDetected,
    ParameterTooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_allow() {
        assert!(Verdict::Allow.is_allowed());
        assert!(!Verdict::Allow.is_denied());
    }

    #[test]
    fn verdict_deny() {
        let v = Verdict::Deny { reason: "nope".into(), code: DenyCode::Unauthorized };
        assert!(v.is_denied());
        assert!(!v.is_allowed());
    }

    #[test]
    fn verdict_flag_is_allowed() {
        let v = Verdict::Flag { reason: "suspicious".into() };
        assert!(v.is_allowed());
        assert!(!v.is_denied());
    }
}
