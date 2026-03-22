use thiserror::Error;

#[derive(Debug, Error)]
pub enum TRonError {
    #[error("policy error: {0}")]
    Policy(String),

    #[error("invalid policy config: {0}")]
    PolicyConfig(String),

    #[error("audit error: {0}")]
    Audit(String),

    #[error("scanner error: {0}")]
    Scanner(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
