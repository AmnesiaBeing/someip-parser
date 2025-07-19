// src/parser/link_layer.rs
use nom::{IResult, Parser, bytes::complete::take, number::complete::be_u16};

#[derive(Debug, Clone, PartialEq)]
pub enum LinkLayer {
    Ethernet(EthernetFrame),
    SLL(SLLHeader),
    // 其他链路层类型可以在此添加
}

#[derive(Debug, Clone, PartialEq)]
pub struct EthernetFrame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub vlan: Option<VlanTag>,
    pub ethertype: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VlanTag {
    pub tci: u16,
    pub ethertype: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SLLHeader {
    pub packet_type: u16,
    pub link_layer_addr_type: u16,
    pub link_layer_addr_len: u16,
    pub link_layer_addr: Vec<u8>,
    pub protocol: u16,
    pub payload: Vec<u8>,
}

pub fn parse_link_layer(input: &[u8]) -> IResult<&[u8], LinkLayer> {
    // 检查是否为SLL头 (Linux cooked capture)
    if input.len() >= 16 && &input[0..2] == &[0x00, 0x00] {
        return parse_sll(input);
    }

    // 默认尝试解析以太网帧
    parse_ethernet(input)
}

fn parse_ethernet(input: &[u8]) -> IResult<&[u8], LinkLayer> {
    let (input, (dst_mac, src_mac, ethertype)) =
        (take(6usize), take(6usize), be_u16).parse(input)?;

    let (input, vlan) = if ethertype == 0x8100 || ethertype == 0x88A8 || ethertype == 0x9100 {
        // VLAN标签存在
        let (input, (tci, ethertype)) = (be_u16, be_u16).parse(input)?;
        (input, Some(VlanTag { tci, ethertype }))
    } else {
        (input, None)
    };

    let payload = input.to_vec();

    Ok((
        &[],
        LinkLayer::Ethernet(EthernetFrame {
            dst_mac: dst_mac.try_into().unwrap(),
            src_mac: src_mac.try_into().unwrap(),
            vlan: vlan.clone(),
            ethertype: vlan.as_ref().map(|v| v.ethertype).unwrap_or(ethertype),
            payload,
        }),
    ))
}

fn parse_sll(input: &[u8]) -> IResult<&[u8], LinkLayer> {
    let (input, (packet_type, link_layer_addr_type, link_layer_addr_len)) =
        (be_u16, be_u16, be_u16).parse(input)?;

    let (input, link_layer_addr) = take(link_layer_addr_len as usize)(input)?;
    let (input, protocol) = be_u16(input)?;

    let payload = input.to_vec();

    Ok((
        &[],
        LinkLayer::SLL(SLLHeader {
            packet_type,
            link_layer_addr_type,
            link_layer_addr_len,
            link_layer_addr: link_layer_addr.to_vec(),
            protocol,
            payload,
        }),
    ))
}
