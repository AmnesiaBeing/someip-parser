// src/parser/someip/header.rs
use nom::{
    IResult, Parser,
    number::complete::{be_u8, be_u16, be_u32},
};

#[derive(Debug, Clone, PartialEq)]
pub struct SomeIPHeader {
    pub service_id: u16,
    pub method_id: u16,
    pub length: u32,
    pub client_id: u16,
    pub session_id: u16,
    pub protocol_version: u8,
    pub interface_version: u8,
    pub message_type: MessageType,
    pub return_code: ReturnCode,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(u8)]
pub enum MessageType {
    Request = 0x00,
    RequestNoReturn = 0x01,
    Notification = 0x02,
    RequestACK = 0x40,
    RequestNoReturnACK = 0x41,
    NotificationACK = 0x42,
    Response = 0x80,
    Error = 0x81,
    ResponseACK = 0xC0,
    ErrorACK = 0xC1,
    Unknown(u8),
}

impl MessageType {
    pub fn as_u8(&self) -> u8 {
        match self {
            MessageType::Unknown(value) => *value,
            _ => unsafe { std::mem::transmute_copy(self) },
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReturnCode {
    Ok,
    NotOk,
    UnknownService,
    UnknownMethod,
    NotReady,
    NotReachable,
    Timeout,
    WrongProtocolVersion,
    WrongInterfaceVersion,
    MalformedMessage,
    WrongMessageType,
    Unknown(u8),
}

pub fn parse_someip_header(input: &[u8]) -> IResult<&[u8], SomeIPHeader> {
    let (input, (service_id, method_id, length, client_id, session_id)) =
        (be_u16, be_u16, be_u32, be_u16, be_u16).parse(input)?;

    let (input, (protocol_version, interface_version, message_type, return_code)) =
        (be_u8, be_u8, be_u8, be_u8).parse(input)?;

    Ok((
        &input[..],
        SomeIPHeader {
            service_id,
            method_id,
            length,
            client_id,
            session_id,
            protocol_version,
            interface_version,
            message_type: parse_message_type(message_type),
            return_code: parse_return_code(return_code),
        },
    ))
}

fn parse_message_type(value: u8) -> MessageType {
    match value {
        0x00 => MessageType::Request,
        0x01 => MessageType::RequestNoReturn,
        0x02 => MessageType::Notification,
        0x40 => MessageType::RequestACK,
        0x41 => MessageType::RequestNoReturnACK,
        0x42 => MessageType::NotificationACK,
        0x80 => MessageType::Response,
        0x81 => MessageType::Error,
        0xC0 => MessageType::ResponseACK,
        0xC1 => MessageType::ErrorACK,
        _ => MessageType::Unknown(value),
    }
}

pub fn parse_return_code(value: u8) -> ReturnCode {
    match value {
        0x00 => ReturnCode::Ok,
        0x01 => ReturnCode::NotOk,
        0x02 => ReturnCode::UnknownService,
        0x03 => ReturnCode::UnknownMethod,
        0x04 => ReturnCode::NotReady,
        0x05 => ReturnCode::NotReachable,
        0x06 => ReturnCode::Timeout,
        0x07 => ReturnCode::WrongProtocolVersion,
        0x08 => ReturnCode::WrongInterfaceVersion,
        0x09 => ReturnCode::MalformedMessage,
        0x0A => ReturnCode::WrongMessageType,
        _ => ReturnCode::Unknown(value),
    }
}
