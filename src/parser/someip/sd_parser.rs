// src/parser/someip/sd_parser.rs
use super::header::parse_return_code;
use super::header::*;
use nom::{
    IResult, Parser,
    bytes::complete::take,
    multi::{count, many0},
    number::complete::{be_u8, be_u16, be_u24, be_u32},
};

#[derive(Debug, Clone, PartialEq)]
pub struct SDPacket {
    pub header: SomeIPHeader,
    pub flags: SDFlags,
    pub entries: Vec<SDEntry>,
    pub options: Vec<SDOption>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SDFlags {
    pub reboot: bool,
    pub unicast: bool,
    pub explicit_initial_data_control: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SDEntry {
    FindService(FindServiceEntry),
    OfferService(OfferServiceEntry),
    SubscribeEventgroup(SubscribeEventgroupEntry),
    SubscribeEventgroupAck(SubscribeEventgroupAckEntry),
    Unknown { entry_type: u8, data: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq)]
pub struct FindServiceEntry {
    pub service_id: u16,
    pub instance_id: u16,
    pub major_version: u8,
    pub ttl: u32,
    pub minor_version: u32,
    pub first_options_index: u8,
    pub number_of_first_options: u8,
    pub second_options_index: u8,
    pub number_of_second_options: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OfferServiceEntry {
    pub service_id: u16,
    pub instance_id: u16,
    pub major_version: u8,
    pub ttl: u32,
    pub minor_version: u32,
    pub first_options_index: u8,
    pub number_of_first_options: u8,
    pub second_options_index: u8,
    pub number_of_second_options: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SubscribeEventgroupEntry {
    pub service_id: u16,
    pub instance_id: u16,
    pub major_version: u8,
    pub ttl: u32,
    pub eventgroup_id: u16,
    pub reserved: u16,
    pub first_options_index: u8,
    pub number_of_first_options: u8,
    pub second_options_index: u8,
    pub number_of_second_options: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SubscribeEventgroupAckEntry {
    pub service_id: u16,
    pub instance_id: u16,
    pub major_version: u8,
    pub ttl: u32,
    pub eventgroup_id: u16,
    pub reserved: u16,
    pub first_options_index: u8,
    pub number_of_first_options: u8,
    pub second_options_index: u8,
    pub number_of_second_options: u8,
    pub return_code: ReturnCode,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SDOption {
    Configuration(ConfigurationOption),
    LoadBalancing(LoadBalancingOption),
    Ipv4Endpoint(Ipv4EndpointOption),
    Ipv6Endpoint(Ipv6EndpointOption),
    Ipv4Multicast(Ipv4MulticastOption),
    Ipv6Multicast(Ipv6MulticastOption),
    Ipv4SDEndpoint(Ipv4SDEndpointOption),
    Ipv6SDEndpoint(Ipv6SDEndpointOption),
    Unknown { option_type: u8, data: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConfigurationOption {
    pub items: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoadBalancingOption {
    pub strategy: u8,
    pub priority: u16,
    pub weight: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ipv4EndpointOption {
    pub ip_address: [u8; 4],
    pub transport_protocol: TransportProtocol,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ipv6EndpointOption {
    pub ip_address: [u8; 16],
    pub transport_protocol: TransportProtocol,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ipv4MulticastOption {
    pub ip_address: [u8; 4],
    pub transport_protocol: TransportProtocol,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ipv6MulticastOption {
    pub ip_address: [u8; 16],
    pub transport_protocol: TransportProtocol,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ipv4SDEndpointOption {
    pub ip_address: [u8; 4],
    pub transport_protocol: TransportProtocol,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ipv6SDEndpointOption {
    pub ip_address: [u8; 16],
    pub transport_protocol: TransportProtocol,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransportProtocol {
    TCP,
    UDP,
    Unknown(u8),
}

pub fn parse_sd_packet(input: &[u8], header: SomeIPHeader) -> IResult<&[u8], SDPacket> {
    let (input, flags_byte) = be_u8(input)?;
    let flags = SDFlags {
        reboot: (flags_byte & 0x80) != 0,
        unicast: (flags_byte & 0x40) != 0,
        explicit_initial_data_control: (flags_byte & 0x20) != 0,
    };

    // 跳过保留字段 (3字节)
    let (input, _) = take(3usize)(input)?;

    // 读取条目数组长度 (4字节)
    let (input, entries_length) = be_u32(input)?;

    // 计算条目数量 (每个条目16字节)
    let entries_count = entries_length as usize / 16;

    // 解析条目
    let (input, entries) = count(parse_sd_entry, entries_count).parse(input)?;

    // 读取选项数组长度 (4字节)
    let (input, options_length) = be_u32(input)?;

    // 解析选项
    let (input, options) = parse_sd_options(input, options_length as usize)?;

    Ok((
        input,
        SDPacket {
            header,
            flags,
            entries,
            options,
        },
    ))
}

fn parse_sd_entry(input: &[u8]) -> IResult<&[u8], SDEntry> {
    let (input, entry_type) = be_u8(input)?;
    let (input, (first_options_index, second_options_index)) = (be_u8, be_u8).parse(input)?;
    let (input, options_count_byte) = be_u8(input)?;
    let number_of_first_options = options_count_byte & 0x0F;
    let number_of_second_options = (options_count_byte >> 4) & 0x0F;

    let (input, (service_id, instance_id)) = (be_u16, be_u16).parse(input)?;
    let (input, major_version) = be_u8(input)?;
    let (input, ttl) = be_u24(input)?;

    match entry_type {
        0x00 => {
            // FindService
            let (input, minor_version) = be_u32(input)?;
            Ok((
                input,
                SDEntry::FindService(FindServiceEntry {
                    service_id,
                    instance_id,
                    major_version,
                    ttl,
                    minor_version,
                    first_options_index,
                    number_of_first_options,
                    second_options_index,
                    number_of_second_options,
                }),
            ))
        }
        0x01 => {
            // OfferService
            let (input, minor_version) = be_u32(input)?;
            Ok((
                input,
                SDEntry::OfferService(OfferServiceEntry {
                    service_id,
                    instance_id,
                    major_version,
                    ttl,
                    minor_version,
                    first_options_index,
                    number_of_first_options,
                    second_options_index,
                    number_of_second_options,
                }),
            ))
        }
        0x06 => {
            // SubscribeEventgroup
            let (input, (reserved, eventgroup_id)) = (be_u16, be_u16).parse(input)?;
            Ok((
                input,
                SDEntry::SubscribeEventgroup(SubscribeEventgroupEntry {
                    service_id,
                    instance_id,
                    major_version,
                    ttl,
                    eventgroup_id,
                    reserved,
                    first_options_index,
                    number_of_first_options,
                    second_options_index,
                    number_of_second_options,
                }),
            ))
        }
        0x07 => {
            // SubscribeEventgroupAck
            let (input, (reserved, eventgroup_id)) = (be_u16, be_u16).parse(input)?;
            let (input, return_code) = be_u8(input)?;
            Ok((
                input,
                SDEntry::SubscribeEventgroupAck(SubscribeEventgroupAckEntry {
                    service_id,
                    instance_id,
                    major_version,
                    ttl,
                    eventgroup_id,
                    reserved,
                    first_options_index,
                    number_of_first_options,
                    second_options_index,
                    number_of_second_options,
                    return_code: parse_return_code(return_code),
                }),
            ))
        }
        _ => {
            // Unknown entry type
            let (input, data) = take(8usize)(input)?;
            Ok((
                input,
                SDEntry::Unknown {
                    entry_type,
                    data: data.to_vec(),
                },
            ))
        }
    }
}

fn parse_sd_options(input: &[u8], length: usize) -> IResult<&[u8], Vec<SDOption>> {
    let mut options = Vec::new();
    let mut remaining = &input[..length];

    while remaining.len() >= 4 {
        let (rest, option_length) = be_u16(remaining)?;
        let option_length = option_length as usize;

        if option_length < 4 || option_length > remaining.len() {
            break;
        }

        let (rest, option_type) = be_u8(rest)?;
        let (rest, _reserved) = be_u8(rest)?;

        let option_data = &rest[..(option_length - 4)];

        let (_remaining_option_data, option) = match option_type {
            0x01 => parse_configuration_option(option_data)?,
            0x02 => parse_load_balancing_option(option_data)?,
            0x04 => parse_ipv4_endpoint_option(option_data)?,
            0x06 => parse_ipv6_endpoint_option(option_data)?,
            0x14 => parse_ipv4_multicast_option(option_data)?,
            0x16 => parse_ipv6_multicast_option(option_data)?,
            0x24 => parse_ipv4_sd_endpoint_option(option_data)?,
            0x26 => parse_ipv6_sd_endpoint_option(option_data)?,
            _ => (
                rest,
                SDOption::Unknown {
                    option_type,
                    data: option_data.to_vec(),
                },
            ),
        };

        options.push(option);
        remaining = &rest[(option_length - 4)..];
    }

    Ok((&input[length..], options))
}

fn parse_configuration_option(input: &[u8]) -> IResult<&[u8], SDOption> {
    let (input, items) = many0(parse_configuration_item).parse(input)?;
    Ok((
        input,
        SDOption::Configuration(ConfigurationOption { items }),
    ))
}

fn parse_configuration_item(input: &[u8]) -> IResult<&[u8], String> {
    let (input, length) = be_u16(input)?;
    let length = length as usize;

    if length > input.len() {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Eof,
        )));
    }

    let (input, item_data) = take(length)(input)?;
    let item = String::from_utf8_lossy(item_data).into_owned();

    Ok((input, item))
}

fn parse_load_balancing_option(input: &[u8]) -> IResult<&[u8], SDOption> {
    let (input, strategy) = be_u8(input)?;
    let (input, priority) = be_u16(input)?;
    let (input, weight) = be_u16(input)?;

    Ok((
        input,
        SDOption::LoadBalancing(LoadBalancingOption {
            strategy,
            priority,
            weight,
        }),
    ))
}

fn parse_ipv4_endpoint_option(input: &[u8]) -> IResult<&[u8], SDOption> {
    let (input, ip_bytes) = take(4usize)(input)?;
    let ip_address: [u8; 4] = ip_bytes.try_into().unwrap();

    let (input, protocol) = be_u8(input)?;
    let transport_protocol = match protocol {
        0x06 => TransportProtocol::TCP,
        0x11 => TransportProtocol::UDP,
        _ => TransportProtocol::Unknown(protocol),
    };

    let (input, port) = be_u16(input)?;

    Ok((
        input,
        SDOption::Ipv4Endpoint(Ipv4EndpointOption {
            ip_address,
            transport_protocol,
            port,
        }),
    ))
}

fn parse_ipv6_endpoint_option(input: &[u8]) -> IResult<&[u8], SDOption> {
    let (input, ip_bytes) = take(16usize)(input)?;
    let ip_address: [u8; 16] = ip_bytes.try_into().unwrap();

    let (input, protocol) = be_u8(input)?;
    let transport_protocol = match protocol {
        0x06 => TransportProtocol::TCP,
        0x11 => TransportProtocol::UDP,
        _ => TransportProtocol::Unknown(protocol),
    };

    let (input, port) = be_u16(input)?;

    Ok((
        input,
        SDOption::Ipv6Endpoint(Ipv6EndpointOption {
            ip_address,
            transport_protocol,
            port,
        }),
    ))
}

fn parse_ipv4_multicast_option(input: &[u8]) -> IResult<&[u8], SDOption> {
    let (input, ip_bytes) = take(4usize)(input)?;
    let ip_address: [u8; 4] = ip_bytes.try_into().unwrap();

    let (input, protocol) = be_u8(input)?;
    let transport_protocol = match protocol {
        0x06 => TransportProtocol::TCP,
        0x11 => TransportProtocol::UDP,
        _ => TransportProtocol::Unknown(protocol),
    };

    let (input, port) = be_u16(input)?;

    Ok((
        input,
        SDOption::Ipv4Multicast(Ipv4MulticastOption {
            ip_address,
            transport_protocol,
            port,
        }),
    ))
}

fn parse_ipv6_multicast_option(input: &[u8]) -> IResult<&[u8], SDOption> {
    let (input, ip_bytes) = take(16usize)(input)?;
    let ip_address: [u8; 16] = ip_bytes.try_into().unwrap();

    let (input, protocol) = be_u8(input)?;
    let transport_protocol = match protocol {
        0x06 => TransportProtocol::TCP,
        0x11 => TransportProtocol::UDP,
        _ => TransportProtocol::Unknown(protocol),
    };

    let (input, port) = be_u16(input)?;

    Ok((
        input,
        SDOption::Ipv6Multicast(Ipv6MulticastOption {
            ip_address,
            transport_protocol,
            port,
        }),
    ))
}

fn parse_ipv4_sd_endpoint_option(input: &[u8]) -> IResult<&[u8], SDOption> {
    let (input, ip_bytes) = take(4usize)(input)?;
    let ip_address: [u8; 4] = ip_bytes.try_into().unwrap();

    let (input, protocol) = be_u8(input)?;
    let transport_protocol = match protocol {
        0x06 => TransportProtocol::TCP,
        0x11 => TransportProtocol::UDP,
        _ => TransportProtocol::Unknown(protocol),
    };

    let (input, port) = be_u16(input)?;

    Ok((
        input,
        SDOption::Ipv4SDEndpoint(Ipv4SDEndpointOption {
            ip_address,
            transport_protocol,
            port,
        }),
    ))
}

fn parse_ipv6_sd_endpoint_option(input: &[u8]) -> IResult<&[u8], SDOption> {
    let (input, ip_bytes) = take(16usize)(input)?;
    let ip_address: [u8; 16] = ip_bytes.try_into().unwrap();

    let (input, protocol) = be_u8(input)?;
    let transport_protocol = match protocol {
        0x06 => TransportProtocol::TCP,
        0x11 => TransportProtocol::UDP,
        _ => TransportProtocol::Unknown(protocol),
    };

    let (input, port) = be_u16(input)?;

    Ok((
        input,
        SDOption::Ipv6SDEndpoint(Ipv6SDEndpointOption {
            ip_address,
            transport_protocol,
            port,
        }),
    ))
}
