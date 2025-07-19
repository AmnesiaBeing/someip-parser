// src/parser/someip/tp_parser.rs
use super::header::*;
use crate::error::{Result, SomeIPError};
use bytes::Bytes;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub struct TPSegment {
    pub header: SomeIPHeader,
    pub is_first: bool,
    pub is_last: bool,
    pub offset: u32,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReassembledMessage {
    pub header: SomeIPHeader,
    pub payload: Vec<u8>,
}

#[derive(Clone)]
struct PendingMessage {
    header: SomeIPHeader,
    segments: HashMap<u32, Bytes>, // 偏移量 -> 数据
    expected_offset: u32,
    total_size: Option<u32>,
    last_updated: Instant,
}

pub struct TPParser {
    pending_messages: HashMap<(u16, u16, u16), PendingMessage>, // (服务ID, 客户端ID, 会话ID) -> 待重组消息
    timeout: Duration,
}

impl TPParser {
    pub fn new(timeout: Duration) -> Self {
        Self {
            pending_messages: HashMap::new(),
            timeout,
        }
    }

    pub fn process_segment(&mut self, segment: TPSegment) -> Result<Option<ReassembledMessage>> {
        let key = (
            segment.header.service_id,
            segment.header.client_id,
            segment.header.session_id,
        );

        // 检查是否需要清理超时的待重组消息
        self.cleanup_expired_messages();

        // 处理第一个分段
        if segment.is_first {
            let total_size = if segment.is_last {
                // 单段消息
                segment.offset + segment.payload.len() as u32
            } else {
                // 多段消息，第一个分段包含完整长度
                segment.header.length - 8 // 减去头部大小
            };

            self.pending_messages.insert(
                key,
                PendingMessage {
                    header: segment.header.clone(),
                    segments: HashMap::from([(segment.offset, segment.payload.clone())]),
                    expected_offset: segment.offset + segment.payload.len() as u32,
                    total_size: Some(total_size),
                    last_updated: Instant::now(),
                },
            );

            // 如果是单段消息，直接返回
            if segment.is_last {
                return Ok(Some(ReassembledMessage {
                    header: segment.header,
                    payload: segment.payload.to_vec(),
                }));
            }

            return Ok(None);
        }

        // 处理非第一个分段
        let pending_msg = match self.pending_messages.get_mut(&key) {
            Some(msg) => msg,
            None => {
                // 收到非第一个分段，但没有对应的第一个分段，丢弃
                return Ok(None);
            }
        };

        // 更新最后更新时间
        pending_msg.last_updated = Instant::now();

        // 检查偏移量是否符合预期
        if segment.offset != pending_msg.expected_offset {
            // 乱序分段，先缓存
            pending_msg.segments.insert(segment.offset, segment.payload);
            return Ok(None);
        }

        // 正常顺序的分段
        let payload = segment.payload.clone();
        pending_msg.segments.insert(segment.offset, payload.clone());
        pending_msg.expected_offset += payload.len() as u32;

        // 检查是否是最后一个分段
        if segment.is_last {
            pending_msg.total_size = Some(segment.offset + segment.payload.len() as u32);
        }

        // 检查是否可以重组完整消息
        if let Some(total_size) = pending_msg.total_size {
            if pending_msg.expected_offset >= total_size {
                // 所有分段都已收到，进行重组
                let pending_msg_clone = pending_msg.clone();
                self.pending_messages.remove(&key);
                let reassembled = self.reassemble_message(&pending_msg_clone)?;
                return Ok(Some(reassembled));
            }
        }

        Ok(None)
    }

    fn reassemble_message(&self, pending_msg: &PendingMessage) -> Result<ReassembledMessage> {
        let mut offset = 0;
        let total_size = pending_msg.total_size.ok_or_else(|| {
            SomeIPError::TPSegmentError("Missing total size when reassembling message".to_string())
        })? as usize;

        let mut payload = vec![0; total_size];

        // 按偏移量顺序组装数据
        let mut segments: Vec<_> = pending_msg.segments.iter().collect();
        segments.sort_by_key(|(off, _)| *off);

        for (seg_offset, data) in segments {
            let len = data.len();
            payload[*seg_offset as usize..(*seg_offset as usize + len)]
                .copy_from_slice(&data[..len]);
            offset += len as u32;
        }

        Ok(ReassembledMessage {
            header: pending_msg.header.clone(),
            payload,
        })
    }

    fn cleanup_expired_messages(&mut self) {
        let now = Instant::now();
        self.pending_messages
            .retain(|_, msg| now.duration_since(msg.last_updated) <= self.timeout);
    }
}

pub fn parse_tp_segment(payload: &[u8], header: SomeIPHeader) -> Result<TPSegment> {
    if payload.len() < 5 {
        return Err(SomeIPError::TPSegmentError(
            "Invalid TP segment: insufficient length".to_string(),
        )
        .into());
    }

    let first_byte = payload[0];
    let is_first = (first_byte & 0x80) != 0;
    let is_last = (first_byte & 0x40) != 0;

    // 解析偏移量
    let offset = if is_first {
        // 第一个分段使用3字节偏移量
        ((first_byte & 0x3F) as u32) << 16 | (payload[1] as u32) << 8 | payload[2] as u32
    } else {
        // 后续分段使用4字节偏移量
        (payload[0] as u32) << 24
            | (payload[1] as u32) << 16
            | (payload[2] as u32) << 8
            | payload[3] as u32
    };

    // 提取数据部分
    let data_offset = if is_first { 3 } else { 4 };
    let data = &payload[data_offset..];

    Ok(TPSegment {
        header,
        is_first,
        is_last,
        offset,
        payload: Bytes::copy_from_slice(data),
    })
}
