// src/output/exporter.rs
use super::formatter::*;
use crate::error::Result;
use std::fs::File;
use std::io::{self, Write};

pub struct Exporter {
    formatter: Box<dyn Formatter>,
    output_path: Option<String>,
}

impl Exporter {
    pub fn new(formatter: Box<dyn Formatter>, output_path: Option<String>) -> Self {
        Self {
            formatter,
            output_path,
        }
    }

    pub fn export(&self, messages: &[FormattedMessage]) -> Result<()> {
        let formatted = self.formatter.format(messages)?;

        if let Some(path) = &self.output_path {
            // 输出到文件
            let mut file = File::create(path)?;
            file.write_all(formatted.as_bytes())?;
            log::info!("Exported results to {}", path);
        } else {
            // 输出到标准输出
            io::stdout().write_all(formatted.as_bytes())?;
        }

        Ok(())
    }
}
