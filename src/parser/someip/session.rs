// src/parser/someip/session.rs
use super::header::*;
use crate::error::{Result, SomeIPError};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime};

#[derive(Debug, Clone, PartialEq)]
pub struct RequestResponsePair {
    pub request: SomeIPMessage,
    pub response: Option<SomeIPMessage>,
    pub timeout: Instant,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SomeIPMessage {
    pub timestamp: SystemTime,
    pub header: SomeIPHeader,
    pub payload: Vec<u8>,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
}

pub struct SessionManager {
    sessions: HashMap<(u16, u16, u16), RequestResponsePair>, // (服务ID, 客户端ID, 会话ID) -> 会话
    timeout: Duration,
    max_pairs: usize,
    pending_responses: VecDeque<(u16, u16, u16)>, // 等待响应的请求
}

impl SessionManager {
    pub fn new(timeout: Duration, max_pairs: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            timeout,
            max_pairs,
            pending_responses: VecDeque::new(),
        }
    }

    pub fn add_request(&mut self, message: SomeIPMessage) -> Result<()> {
        // 检查是否需要移除最旧的会话
        if self.sessions.len() >= self.max_pairs {
            // 移除最旧的待响应请求
            while let Some(key) = self.pending_responses.pop_front() {
                if self.sessions.contains_key(&key) {
                    self.sessions.remove(&key);
                    break;
                }
            }
        }

        let key = (
            message.header.service_id,
            message.header.client_id,
            message.header.session_id,
        );

        // 添加新会话
        self.sessions.insert(
            key,
            RequestResponsePair {
                request: message,
                response: None,
                timeout: Instant::now() + self.timeout,
            },
        );

        // 添加到待响应队列
        self.pending_responses.push_back(key);

        Ok(())
    }

    pub fn add_response(&mut self, message: SomeIPMessage) -> Result<Option<RequestResponsePair>> {
        let key = (
            message.header.service_id,
            message.header.client_id,
            message.header.session_id,
        );

        // 查找对应的请求
        if let Some(pair) = self.sessions.get_mut(&key) {
            // 检查是否是响应消息类型
            match message.header.message_type {
                MessageType::Response | MessageType::Error => {
                    // 添加响应
                    pair.response = Some(message);

                    // 从待响应队列中移除
                    if let Some(pos) = self.pending_responses.iter().position(|&k| k == key) {
                        self.pending_responses.remove(pos);
                    }

                    return Ok(Some(pair.clone()));
                }
                _ => {
                    return Err(SomeIPError::InvalidPacketFormat(
                        "Expected response message type".to_string(),
                    )
                    .into());
                }
            }
        }

        // 没有找到对应的请求
        log::warn!("Response received without matching request: {:?}", key);
        Ok(None)
    }

    pub fn get_pending_requests(&self) -> Vec<RequestResponsePair> {
        self.sessions
            .values()
            .filter(|pair| pair.response.is_none() && pair.timeout > Instant::now())
            .cloned()
            .collect()
    }

    pub fn cleanup_expired_sessions(&mut self) -> Vec<RequestResponsePair> {
        let now = Instant::now();
        let expired: Vec<_> = self
            .sessions
            .iter()
            .filter(|(_, pair)| pair.response.is_none() && pair.timeout <= now)
            .map(|(&key, _)| key)
            .collect();

        let mut result = Vec::new();

        for key in expired {
            if let Some(pair) = self.sessions.remove(&key) {
                // 从待响应队列中移除
                if let Some(pos) = self.pending_responses.iter().position(|&k| k == key) {
                    self.pending_responses.remove(pos);
                }
                result.push(pair);
            }
        }

        result
    }
}
