use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TRonError {
    #[error("policy error: {0}")]
    Policy(String),

    #[error("invalid policy config: {0}")]
    PolicyConfig(String),

    #[error("audit error: {0}")]
    Audit(String),

    #[error("scanner error: {0}")]
    Scanner(String),

    #[error("signature error: {0}")]
    Signature(String),

    #[error("export error: {0}")]
    Export(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
