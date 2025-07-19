// src/parser/network_layer.rs
use nom::{
    IResult,
    bytes::complete::take,
    combinator::{map, opt},
    number::complete::{be_i8, be_u8, be_u16, be_u32},
    sequence::{preceded, tuple},
};
use pnet::packet::{
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
};

#[derive(Debug, Clone, PartialEq)]
pub enum NetworkLayer {
    IPv4(IPv4PacketInfo),
    IPv6(IPv6PacketInfo),
}

#[derive(Debug, Clone, PartialEq)]
pub struct IPv4PacketInfo {
    pub version: u8,
    pub header_length: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: IpNextHeaderProtocol,
    pub checksum: u16,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IPv6PacketInfo {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: IpNextHeaderProtocol,
    pub hop_limit: u8,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub payload: Vec<u8>,
}

pub fn parse_network_layer(input: &[u8], ethertype: u16) -> IResult<&[u8], NetworkLayer> {
    match ethertype {
        0x0800 => parse_ipv4(input),
        0x86DD => parse_ipv6(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        ))),
    }
}

fn parse_ipv4(input: &[u8]) -> IResult<&[u8], NetworkLayer> {
    let (input, version_ihl) = be_u8(input)?;
    let version = version_ihl >> 4;
    let ihl = version_ihl & 0x0F;

    let (input, dscp_ecn) = be_u8(input)?;
    let dscp = dscp_ecn >> 2;
    let ecn = dscp_ecn & 0x03;

    let (input, total_length) = be_u16(input)?;
    let (input, identification) = be_u16(input)?;
    let (input, flags_fragment) = be_u16(input)?;
    let flags = (flags_fragment >> 13) as u8;
    let fragment_offset = flags_fragment & 0x1FFF;

    let (input, ttl) = be_u8(input)?;
    let (input, protocol_num) = be_u8(input)?;
    let protocol = IpNextHeaderProtocol(protocol_num);
    let (input, checksum) = be_u16(input)?;
    let (input, src_ip) = take(4usize)(input)?;
    let (input, dst_ip) = take(4usize)(input)?;

    let header_length_bytes = ihl * 4;
    let payload_start = header_length_bytes as usize;
    let payload = &input[..(total_length as usize - payload_start)];

    Ok((
        &[],
        NetworkLayer::IPv4(IPv4PacketInfo {
            version,
            header_length: ihl,
            dscp,
            ecn,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            src_ip: src_ip.try_into().unwrap(),
            dst_ip: dst_ip.try_into().unwrap(),
            payload: payload.to_vec(),
        }),
    ))
}

fn parse_ipv6(input: &[u8]) -> IResult<&[u8], NetworkLayer> {
    let (input, version_tc_fl) = be_u32(input)?;
    let version = (version_tc_fl >> 28) as u8;
    let traffic_class = ((version_tc_fl >> 20) & 0xFF) as u8;
    let flow_label = version_tc_fl & 0x000FFFFF;

    let (input, payload_length) = be_u16(input)?;
    let (input, next_header_num) = be_u8(input)?;
    let next_header = IpNextHeaderProtocol(next_header_num);
    let (input, hop_limit) = be_u8(input)?;
    let (input, src_ip) = take(16usize)(input)?;
    let (input, dst_ip) = take(16usize)(input)?;

    let payload = input.to_vec();

    Ok((
        &[],
        NetworkLayer::IPv6(IPv6PacketInfo {
            version,
            traffic_class,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            src_ip: src_ip.try_into().unwrap(),
            dst_ip: dst_ip.try_into().unwrap(),
            payload,
        }),
    ))
}
