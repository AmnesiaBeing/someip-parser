// src/parser/transport_layer.rs
use nom::{
    IResult, Parser,
    bytes::complete::take,
    number::complete::{be_u16, be_u32},
};

#[derive(Debug, Clone, PartialEq)]
pub enum TransportLayer {
    UDP(UDPPacketInfo),
    TCP(TCPPacketInfo),
}

#[derive(Debug, Clone, PartialEq)]
pub struct UDPPacketInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TCPPacketInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub reserved: u8,
    pub flags: TCPFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    pub options: Vec<u8>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TCPFlags {
    pub ns: bool,
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

pub fn parse_transport_layer(input: &[u8], protocol: u8) -> IResult<&[u8], TransportLayer> {
    match protocol {
        17 => parse_udp(input),
        6 => parse_tcp(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        ))),
    }
}

fn parse_udp(input: &[u8]) -> IResult<&[u8], TransportLayer> {
    let (input, (src_port, dst_port, length, checksum)) =
        (be_u16, be_u16, be_u16, be_u16).parse(input)?;

    let payload = input.to_vec();

    Ok((
        &[],
        TransportLayer::UDP(UDPPacketInfo {
            src_port,
            dst_port,
            length,
            checksum,
            payload,
        }),
    ))
}

fn parse_tcp(input: &[u8]) -> IResult<&[u8], TransportLayer> {
    let (input, (src_port, dst_port, seq_num, ack_num)) =
        (be_u16, be_u16, be_u32, be_u32).parse(input)?;

    let (input, data_offset_reserved_flags) = be_u16(input)?;
    let data_offset = ((data_offset_reserved_flags >> 12) & 0x0F) as u8;
    let reserved = ((data_offset_reserved_flags >> 6) & 0x3F) as u8;

    let flags = TCPFlags {
        ns: (data_offset_reserved_flags & 0x0020) != 0,
        cwr: (data_offset_reserved_flags & 0x0010) != 0,
        ece: (data_offset_reserved_flags & 0x0008) != 0,
        urg: (data_offset_reserved_flags & 0x0004) != 0,
        ack: (data_offset_reserved_flags & 0x0002) != 0,
        psh: (data_offset_reserved_flags & 0x0001) != 0,
        rst: (data_offset_reserved_flags & 0x0000) != 0,
        syn: (data_offset_reserved_flags & 0x0000) != 0,
        fin: (data_offset_reserved_flags & 0x0000) != 0,
    };

    let (input, (window_size, checksum, urgent_ptr)) = (be_u16, be_u16, be_u16).parse(input)?;

    let options_size = (data_offset * 4 - 20) as usize;
    let (input, options) = if options_size > 0 {
        take(options_size)(input)?
    } else {
        (&input[..0], &[][..])
    };

    let payload = input.to_vec();

    Ok((
        &[],
        TransportLayer::TCP(TCPPacketInfo {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            data_offset,
            reserved,
            flags,
            window_size,
            checksum,
            urgent_ptr,
            options: options.to_vec(),
            payload,
        }),
    ))
}
