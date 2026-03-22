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

/// High-level verdict kind (for audit storage without carrying payload).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictKind {
    Allow,
    Deny,
    Flag,
}

impl Verdict {
    pub fn kind(&self) -> VerdictKind {
        match self {
            Self::Allow => VerdictKind::Allow,
            Self::Deny { .. } => VerdictKind::Deny,
            Self::Flag { .. } => VerdictKind::Flag,
        }
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

impl DenyCode {
    /// Stable label for JSON-RPC error messages and audit details.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::RateLimited => "rate_limited",
            Self::InjectionDetected => "injection_detected",
            Self::ToolDisabled => "tool_disabled",
            Self::AnomalyDetected => "anomaly_detected",
            Self::ParameterTooLarge => "parameter_too_large",
        }
    }
}

impl std::fmt::Display for DenyCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
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
        let v = Verdict::Deny {
            reason: "nope".into(),
            code: DenyCode::Unauthorized,
        };
        assert!(v.is_denied());
        assert!(!v.is_allowed());
    }

    #[test]
    fn verdict_flag_is_allowed() {
        let v = Verdict::Flag {
            reason: "suspicious".into(),
        };
        assert!(v.is_allowed());
        assert!(!v.is_denied());
    }

    #[test]
    fn verdict_kind_mapping() {
        assert_eq!(Verdict::Allow.kind(), VerdictKind::Allow);
        assert_eq!(
            Verdict::Deny {
                reason: "x".into(),
                code: DenyCode::Unauthorized
            }
            .kind(),
            VerdictKind::Deny
        );
        assert_eq!(
            Verdict::Flag { reason: "x".into() }.kind(),
            VerdictKind::Flag
        );
    }

    #[test]
    fn verdict_serde_roundtrip() {
        let verdicts = vec![
            Verdict::Allow,
            Verdict::Deny {
                reason: "bad".into(),
                code: DenyCode::InjectionDetected,
            },
            Verdict::Flag {
                reason: "sus".into(),
            },
        ];
        for v in &verdicts {
            let json = serde_json::to_string(v).unwrap();
            let back: Verdict = serde_json::from_str(&json).unwrap();
            assert_eq!(v.is_allowed(), back.is_allowed());
            assert_eq!(v.is_denied(), back.is_denied());
        }
    }

    #[test]
    fn tool_call_serde_roundtrip() {
        let call = ToolCall {
            agent_id: "agent-1".into(),
            tool_name: "tarang_probe".into(),
            params: serde_json::json!({"key": "value"}),
            timestamp: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&call).unwrap();
        let back: ToolCall = serde_json::from_str(&json).unwrap();
        assert_eq!(call.agent_id, back.agent_id);
        assert_eq!(call.tool_name, back.tool_name);
    }

    #[test]
    fn deny_code_all_variants() {
        let codes = [
            DenyCode::Unauthorized,
            DenyCode::RateLimited,
            DenyCode::InjectionDetected,
            DenyCode::ToolDisabled,
            DenyCode::AnomalyDetected,
            DenyCode::ParameterTooLarge,
        ];
        for code in &codes {
            let json = serde_json::to_string(code).unwrap();
            let back: DenyCode = serde_json::from_str(&json).unwrap();
            assert_eq!(*code, back);
        }
    }
}
