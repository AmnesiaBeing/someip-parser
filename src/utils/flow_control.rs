// src/utils/flow_control.rs
use super::super::parser::transport_layer::*;
use crate::error::Result;
use bytes::Bytes;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TcpConnectionKey {
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
}

struct TcpSegment {
    seq_num: u32,
    data: Bytes,
    timestamp: Instant,
}

struct TcpStream {
    segments: VecDeque<TcpSegment>,
    expected_seq: u32,
    window_size: u16,
    last_activity: Instant,
    closed: bool,
    fin_seq: Option<u32>,
}

pub struct TcpFlowController {
    connections: HashMap<TcpConnectionKey, TcpStream>,
    max_connections: usize,
    segment_timeout: Duration,
    connection_timeout: Duration,
}

impl TcpFlowController {
    pub fn new(
        max_connections: usize,
        segment_timeout: Duration,
        connection_timeout: Duration,
    ) -> Self {
        Self {
            connections: HashMap::new(),
            max_connections,
            segment_timeout,
            connection_timeout,
        }
    }

    pub fn process_tcp_packet(
        &mut self,
        src_ip: &str,
        dst_ip: &str,
        tcp_packet: &TCPPacketInfo,
        payload: Bytes,
    ) -> Result<Option<Bytes>> {
        let key = TcpConnectionKey {
            src_ip: src_ip.to_string(),
            src_port: tcp_packet.src_port,
            dst_ip: dst_ip.to_string(),
            dst_port: tcp_packet.dst_port,
        };

        // 清理超时的连接
        self.cleanup_expired_connections();

        // 如果达到最大连接数，移除最旧的连接
        if self.connections.len() >= self.max_connections {
            if let Some(oldest_key) = self
                .connections
                .iter()
                .min_by_key(|(_, stream)| stream.last_activity)
                .map(|(key, _)| key.clone())
            {
                self.connections.remove(&oldest_key);
            }
        }

        // 获取或创建TCP流
        let stream = self
            .connections
            .entry(key.clone())
            .or_insert_with(|| TcpStream {
                segments: VecDeque::new(),
                expected_seq: tcp_packet.seq_num,
                window_size: tcp_packet.window_size,
                last_activity: Instant::now(),
                closed: false,
                fin_seq: None,
            });
        let stream = stream;
        let stream = stream as *mut TcpStream;
        // SAFETY: We have exclusive access to self, so this is safe.
        let mut stream = unsafe { &mut *stream };

        // 更新流状态
        stream.last_activity = Instant::now();
        stream.window_size = tcp_packet.window_size;

        // 处理SYN包
        if tcp_packet.flags.syn {
            stream.expected_seq = tcp_packet.seq_num + 1;
            if payload.is_empty() {
                return Ok(None);
            }
        }

        // 处理FIN包
        if tcp_packet.flags.fin {
            stream.fin_seq = Some(tcp_packet.seq_num + payload.len() as u32);
            stream.closed = true;
        }

        // 处理RST包
        if tcp_packet.flags.rst {
            stream.closed = true;
            return Ok(None);
        }

        // 如果有数据，处理数据段
        if !payload.is_empty() {
            // 检查是否是期望的序列号
            if tcp_packet.seq_num == stream.expected_seq {
                // 按序到达的数据
                stream.expected_seq += payload.len() as u32;

                // 检查是否有积压的分段可以合并
                let mut reassembled = payload;
                self.process_out_of_order_segments(key.clone(), &mut stream, &mut reassembled)?;

                return Ok(Some(reassembled));
            } else if tcp_packet.seq_num > stream.expected_seq {
                stream.segments.push_back(TcpSegment {
                    seq_num: tcp_packet.seq_num,
                    data: payload,
                    timestamp: Instant::now(),
                });

                // 排序分段
                stream
                    .segments
                    .make_contiguous()
                    .sort_by_key(|seg| seg.seq_num);
            } else {
                // 重复的数据，丢弃
                log::trace!(
                    "Discarding duplicate TCP segment with seq num {}",
                    tcp_packet.seq_num
                );
            }
        }

        Ok(None)
    }

    fn process_out_of_order_segments(
        &mut self,
        key: TcpConnectionKey,
        stream: &mut TcpStream,
        reassembled: &mut Bytes,
    ) -> Result<()> {
        // 检查是否有积压的分段可以合并
        while let Some(next_segment) = stream.segments.front() {
            if next_segment.seq_num == stream.expected_seq {
                // 下一个分段按序到达
                let segment = stream.segments.pop_front().unwrap();
                let mut buf = reassembled.clone().to_vec();
                buf.extend_from_slice(&segment.data);
                *reassembled = Bytes::from(buf);
                stream.expected_seq += segment.data.len() as u32;
            } else if next_segment.seq_num < stream.expected_seq {
                // 重复的分段，丢弃
                stream.segments.pop_front();
            } else {
                // 后续分段还未准备好
                break;
            }
        }

        // 清理超时的分段
        stream
            .segments
            .retain(|seg| Instant::now().duration_since(seg.timestamp) <= self.segment_timeout);

        Ok(())
    }

    fn cleanup_expired_connections(&mut self) {
        let now = Instant::now();
        self.connections.retain(|_, stream| {
            !stream.closed || now.duration_since(stream.last_activity) <= self.connection_timeout
        });
    }

    pub fn get_connections_count(&self) -> usize {
        self.connections.len()
    }
}
