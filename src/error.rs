// src/error.rs
use anyhow::Error;

pub type Result<T> = anyhow::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum SomeIPError {
    #[error("Invalid packet format: {0}")]
    InvalidPacketFormat(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("TP segment error: {0}")]
    TPSegmentError(String),

    #[error("TCP stream error: {0}")]
    TCPStreamError(String),

    #[error("Matrix file error: {0}")]
    MatrixFileError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}