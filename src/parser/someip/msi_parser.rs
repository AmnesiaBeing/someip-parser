// src/parser/someip/msi_parser.rs
use super::header::*;
use crate::error::{Result, SomeIPError};
use bytes::Bytes;

#[derive(Debug, Clone, PartialEq)]
pub struct MSIPacket {
    pub messages: Vec<MSIMessage>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MSIMessage {
    pub header: SomeIPHeader,
    pub payload: Bytes,
}

pub fn parse_msi_packet(payload: &[u8]) -> Result<MSIPacket> {
    let mut messages = Vec::new();
    let mut remaining = payload;

    while remaining.len() >= 16 {
        // 解析头部
        let (header, _consumed) = parse_someip_header_wrapper(remaining)?;

        // 计算消息总长度（包括头部）
        let message_length = header.length as usize;

        // 确保有足够的数据
        if message_length > remaining.len() {
            return Err(SomeIPError::InvalidPacketFormat(
                "MSI packet truncated: insufficient data for claimed length".to_string(),
            )
            .into());
        }

        // 提取消息数据
        let message_data = &remaining[..message_length];

        // 提取有效载荷（头部之后的数据）
        let payload = Bytes::copy_from_slice(&message_data[16..]);

        messages.push(MSIMessage { header, payload });

        // 移动到下一个消息
        remaining = &remaining[message_length..];
    }

    if !remaining.is_empty() {
        log::warn!(
            "MSI packet has trailing data after last message: {} bytes",
            remaining.len()
        );
    }

    Ok(MSIPacket { messages })
}

// Use the nom parser from the header module directly and convert its result to your own Result type.
fn parse_someip_header_wrapper(input: &[u8]) -> Result<(SomeIPHeader, usize)> {
    // parse_someip_header is assumed to be a nom parser: fn(&[u8]) -> IResult<&[u8], SomeIPHeader>
    match super::header::parse_someip_header(input) {
        Ok((remaining, header)) => {
            let consumed = input.len() - remaining.len();
            Ok((header, consumed))
        }
        Err(e) => Err(SomeIPError::InvalidPacketFormat(format!(
            "Failed to parse SomeIP header: {}",
            e
        ))
        .into()),
    }
}
