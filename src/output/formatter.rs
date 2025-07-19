// src/output/formatter.rs
use super::super::parser::someip::session::*;
use crate::error::Result;
use chrono::DateTime;
use serde::{Serialize, ser::Serializer};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize)]
pub struct FormattedMessage {
    #[serde(serialize_with = "serialize_timestamp")]
    pub timestamp: SystemTime,
    pub sender: String,
    pub receiver: String,
    pub service: String,
    pub method: String,
    pub message_type: String,
    pub return_code: String,
    pub payload: String,
}

pub trait Formatter {
    fn format(&self, messages: &[FormattedMessage]) -> Result<String>;
}

pub struct JsonFormatter {
    pretty: bool,
}

impl JsonFormatter {
    pub fn new(pretty: bool) -> Self {
        Self { pretty }
    }
}

impl Formatter for JsonFormatter {
    fn format(&self, messages: &[FormattedMessage]) -> Result<String> {
        if self.pretty {
            Ok(serde_json::to_string_pretty(messages)?)
        } else {
            Ok(serde_json::to_string(messages)?)
        }
    }
}

pub struct YamlFormatter;

impl YamlFormatter {
    pub fn new() -> Self {
        Self
    }
}

impl Formatter for YamlFormatter {
    fn format(&self, messages: &[FormattedMessage]) -> Result<String> {
        Ok(serde_yaml::to_string(messages)?)
    }
}

pub struct TextFormatter;

impl TextFormatter {
    pub fn new() -> Self {
        Self
    }
}

impl Formatter for TextFormatter {
    fn format(&self, messages: &[FormattedMessage]) -> Result<String> {
        let mut output = String::new();

        for msg in messages {
            output.push_str(&format!(
                "[{timestamp}] {sender} -> {receiver} | {service}:{method} | {type} | {return_code}\n\
                 Payload: {payload}\n\n",
                timestamp = format_timestamp(&msg.timestamp),
                sender = msg.sender,
                receiver = msg.receiver,
                service = msg.service,
                method = msg.method,
                type = msg.message_type,
                return_code = msg.return_code,
                payload = hex::encode(&msg.payload)
            ));
        }

        Ok(output)
    }
}

fn serialize_timestamp<S>(time: &SystemTime, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let timestamp = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| serde::ser::Error::custom("Invalid system time"))?
        .as_secs_f64();

    serializer.serialize_f64(timestamp)
}

fn format_timestamp(time: &SystemTime) -> String {
    let duration = time.duration_since(UNIX_EPOCH).unwrap();
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();

    let datetime = DateTime::from_timestamp(secs as i64, 0).expect("Invalid timestamp");
    format!("{}.{:03}", datetime.format("%Y-%m-%d %H:%M:%S"), millis)
}

pub fn convert_to_formatted(
    message: &SomeIPMessage,
    matrix: &super::super::parser::someip::matrix::Matrix,
) -> FormattedMessage {
    let service_id = message.header.service_id;
    let method_id = message.header.method_id;

    FormattedMessage {
        timestamp: message.timestamp.into(),
        sender: matrix
            .get_ip_name(&message.src_ip)
            .unwrap_or(&message.src_ip)
            .to_string(),
        receiver: matrix
            .get_ip_name(&message.dst_ip)
            .unwrap_or(&message.dst_ip)
            .to_string(),
        service: matrix
            .get_service_name(service_id)
            .unwrap_or(&format!("0x{:04X}", service_id))
            .to_string(),
        method: matrix
            .get_method_name(service_id, method_id)
            .unwrap_or(&format!("0x{:04X}", method_id))
            .to_string(),
        message_type: format!("{:?}", message.header.message_type),
        return_code: format!("{:?}", message.header.return_code),
        payload: hex::encode(&message.payload),
    }
}
