// src/parser/pcap_reader.rs
use pcap::{Capture, Packet};
use std::time::SystemTime;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct RawPacket {
    pub timestamp: SystemTime,
    pub data: Vec<u8>,
}

impl<'a> From<Packet<'a>> for RawPacket {
    fn from(packet: Packet<'a>) -> Self {
        RawPacket {
            timestamp: SystemTime::UNIX_EPOCH
                .checked_add(std::time::Duration::new(
                    packet.header.ts.tv_sec as u64,
                    packet.header.ts.tv_usec as u32 * 1000,
                ))
                .unwrap(),
            data: packet.data.to_vec(),
        }
    }
}

pub struct PCAPReader {
    capture: Capture<pcap::Offline>,
}

impl PCAPReader {
    pub fn new(pcap_file: &str) -> Result<Self, pcap::Error> {
        let capture = Capture::from_file(pcap_file)?;
        Ok(Self { capture })
    }

    pub async fn start(&mut self, tx: mpsc::Sender<RawPacket>) -> Result<(), pcap::Error> {
        while let Ok(packet) = self.capture.next_packet() {
            let raw_packet = RawPacket::from(packet);
            if tx.send(raw_packet).await.is_err() {
                log::warn!("Channel closed, stopping packet processing");
                break;
            }
        }
        Ok(())
    }
}
