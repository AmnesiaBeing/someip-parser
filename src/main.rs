use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, info, warn};
use std::io::Write;
use tokio::sync::mpsc;
use std::time::{Duration, SystemTime};

// 导入核心模块
mod config;
mod error;
mod output;
mod parser;
mod utils;

use config::Config;
use error::SomeIPError;
use output::{exporter::Exporter, formatter::*};
use parser::{
    link_layer::parse_link_layer,
    network_layer::parse_network_layer,
    pcap_reader::{PCAPReader, RawPacket},
    someip::{
        header::parse_someip_header,
        matrix::Matrix,
        msi_parser::parse_msi_packet,
        sd_parser::{SDPacket, parse_sd_packet},
        session::{SessionManager, SomeIPMessage},
        tp_parser::{TPParser, parse_tp_segment},
    },
    transport_layer::parse_transport_layer,
};
use utils::flow_control::TcpFlowController;

#[tokio::main]
async fn main() -> Result<()> {
    // 解析命令行参数try_parse
    let cli = Config::parse();
    cli.validate()?;

    // 初始化日志
    init_logger(cli.verbose);
    info!("SomeIP 解析工具启动");
    debug!("命令行参数: {:?}", cli);

    // 加载矩阵文件（如果提供）
    let mut matrix = Matrix::new();
    if let Some(matrix_path) = &cli.matrix_file {
        info!("加载矩阵文件: {}", matrix_path.display());
        matrix.load_from_file(matrix_path)?;
    }

    // 初始化核心组件
    let (packet_tx, mut packet_rx) = mpsc::channel(1000);
    let mut session_manager = SessionManager::new(
        Duration::from_secs(cli.request_timeout),
        10000, // 最大会话数
    );
    let mut tp_parser = TPParser::new(Duration::from_secs(cli.tp_timeout));
    let mut tcp_flow = TcpFlowController::new(
        100,                                  // 最大TCP连接数
        Duration::from_secs(30),              // 分段超时
        Duration::from_secs(cli.tcp_timeout), // 连接超时
    );
    let mut known_ports = std::collections::HashSet::new();
    known_ports.insert(cli.sd_port); // 初始已知端口：SD端口

    // 启动 PCAP 读取器
    info!("开始读取 PCAP 文件: {}", cli.pcap_file.display());
    let mut pcap_reader = PCAPReader::new(cli.pcap_file.to_str().context("无效的PCAP路径")?)?;
    tokio::spawn(async move {
        if let Err(e) = pcap_reader.start(packet_tx).await {
            warn!("PCAP 读取器错误: {}", e);
        }
    });

    // 处理数据包
    let mut messages = Vec::new();
    while let Some(raw_packet) = packet_rx.recv().await {
        process_raw_packet(
            &raw_packet,
            cli.sd_port,
            cli.vlan,
            &mut known_ports,
            &mut session_manager,
            &mut tp_parser,
            &mut tcp_flow,
            &matrix,
            &mut messages,
        )?;
    }

    // 处理超时的会话
    let timed_out = session_manager.cleanup_expired_sessions();
    info!("处理完成，共 {} 个超时会话", timed_out.len());
    for pair in timed_out {
        messages.push(pair.request);
    }

    // 格式化并导出结果
    info!("解析完成，共处理 {} 个消息", messages.len());
    let formatted = messages
        .iter()
        .map(|msg| convert_to_formatted(msg, &matrix))
        .collect::<Vec<_>>();

    let formatter = match cli.output_format.as_str() {
        "json" => Box::new(JsonFormatter::new(true)) as Box<dyn Formatter>,
        "yaml" => Box::new(YamlFormatter::new()) as Box<dyn Formatter>,
        _ => Box::new(TextFormatter::new()) as Box<dyn Formatter>,
    };

    let exporter = Exporter::new(
        formatter,
        cli.output_file.map(|p| p.to_string_lossy().into_owned()),
    );
    exporter.export(&formatted)?;

    info!("程序正常退出");
    Ok(())
}

/// 处理单个原始数据包
fn process_raw_packet(
    raw_packet: &RawPacket,
    sd_port: u16,
    target_vlan: Option<u16>,
    known_ports: &mut std::collections::HashSet<u16>,
    session_manager: &mut SessionManager,
    tp_parser: &mut TPParser,
    tcp_flow: &mut TcpFlowController,
    matrix: &Matrix,
    messages: &mut Vec<SomeIPMessage>,
) -> Result<()> {
    // 解析链路层
    let (_, link_layer) = parse_link_layer(&raw_packet.data)
        .map_err(|e| SomeIPError::InvalidPacketFormat(format!("链路层解析失败: {}", e)))?;

    // 检查 VLAN 过滤
    let vlan_id = match &link_layer {
        parser::link_layer::LinkLayer::Ethernet(eth) => eth.vlan.as_ref().map(|v| v.tci & 0x0FFF),
        _ => None,
    };
    if let (Some(target), Some(actual)) = (target_vlan, vlan_id) {
        if actual != target {
            return Ok(()); // 跳过不匹配的 VLAN
        }
    }

    // 解析网络层
    let (net_payload, ethertype) = match &link_layer {
        parser::link_layer::LinkLayer::Ethernet(eth) => (eth.payload.as_slice(), eth.ethertype),
        parser::link_layer::LinkLayer::SLL(sll) => (sll.payload.as_slice(), sll.protocol),
    };
    let (_, network_layer) = parse_network_layer(net_payload, ethertype)
        .map_err(|e| SomeIPError::InvalidPacketFormat(format!("网络层解析失败: {}", e)))?;

    // 提取 IP 地址
    let (src_ip, dst_ip, transport_payload, protocol) = match &network_layer {
        parser::network_layer::NetworkLayer::IPv4(ipv4) => (
            format!(
                "{}.{}.{}.{}",
                ipv4.src_ip[0], ipv4.src_ip[1], ipv4.src_ip[2], ipv4.src_ip[3]
            ),
            format!(
                "{}.{}.{}.{}",
                ipv4.dst_ip[0], ipv4.dst_ip[1], ipv4.dst_ip[2], ipv4.dst_ip[3]
            ),
            ipv4.payload.as_slice(),
            ipv4.protocol,
        ),
        parser::network_layer::NetworkLayer::IPv6(ipv6) => (
            format!("{}", std::net::Ipv6Addr::from(ipv6.src_ip)),
            format!("{}", std::net::Ipv6Addr::from(ipv6.dst_ip)),
            ipv6.payload.as_slice(),
            ipv6.next_header,
        ),
    };

    // 解析传输层
    let (_, transport_layer) = parse_transport_layer(transport_payload, protocol)
        .map_err(|e| SomeIPError::InvalidPacketFormat(format!("传输层解析失败: {}", e)))?;

    // 处理 UDP/TCP 数据包
    match &transport_layer {
        parser::transport_layer::TransportLayer::UDP(udp) => {
            // 检查是否是已知端口（SD 端口或从 SD 学习到的端口）
            if !known_ports.contains(&udp.src_port) && !known_ports.contains(&udp.dst_port) {
                return Ok(());
            }

            // 解析 SomeIP 头部
            if udp.payload.len() < 16 {
                debug!("UDP 包长度不足，跳过: {} 字节", udp.payload.len());
                return Ok(());
            }
            let (_, header) = parse_someip_header(&udp.payload).map_err(|e| {
                SomeIPError::InvalidPacketFormat(format!("SomeIP 头部解析失败: {}", e))
            })?;

            // 处理 SD 包（服务发现）
            if (udp.src_port == sd_port || udp.dst_port == sd_port)
                && header.service_id == 0xFFFF
                && header.method_id == 0x8100
            {
                let (_, sd_packet) =
                    parse_sd_packet(&udp.payload[16..], header.clone()).map_err(|e| {
                        SomeIPError::InvalidPacketFormat(format!("SD 包解析失败: {}", e))
                    })?;
                learn_ports_from_sd(&sd_packet, known_ports);
                info!("发现 SD 包，更新已知端口: {:?}", known_ports);
            }

            // 处理 TP 分段包
            let is_tp = (header.message_type.as_u8() & 0x20) != 0; // TP 标志位
            if is_tp {
                let segment = parse_tp_segment(&udp.payload[16..], header.clone())?;
                if let Some(reassembled) = tp_parser.process_segment(segment)? {
                    let msg = create_someip_message(
                        &raw_packet.timestamp,
                        &src_ip,
                        &dst_ip,
                        udp.src_port,
                        udp.dst_port,
                        reassembled.header,
                        reassembled.payload,
                    );
                    handle_someip_message(msg, session_manager, messages)?;
                }
            }
            // 处理 MSI 多服务包
            else if header.service_id == 0xFFFF && header.method_id == 0x8101 {
                let msi_packet = parse_msi_packet(&udp.payload[16..])?;
                info!("解析 MSI 包，包含 {} 个消息", msi_packet.messages.len());
                for msi_msg in msi_packet.messages {
                    let msg = create_someip_message(
                        &raw_packet.timestamp,
                        &src_ip,
                        &dst_ip,
                        udp.src_port,
                        udp.dst_port,
                        msi_msg.header,
                        msi_msg.payload.to_vec(),
                    );
                    handle_someip_message(msg, session_manager, messages)?;
                }
            }
            // 处理普通 SomeIP 包
            else {
                let payload = udp.payload[16..16 + header.length as usize].to_vec();
                let msg = create_someip_message(
                    &raw_packet.timestamp,
                    &src_ip,
                    &dst_ip,
                    udp.src_port,
                    udp.dst_port,
                    header,
                    payload,
                );
                handle_someip_message(msg, session_manager, messages)?;
            }
        }

        parser::transport_layer::TransportLayer::TCP(tcp) => {
            // 仅处理已知端口的 TCP 包
            if !known_ports.contains(&tcp.src_port) && !known_ports.contains(&tcp.dst_port) {
                return Ok(());
            }

            // 处理 TCP 流控与重组
            if let Some(data) = tcp_flow.process_tcp_packet(
                &src_ip,
                &dst_ip,
                tcp,
                bytes::Bytes::copy_from_slice(&tcp.payload),
            )? {
                // 解析重组后的 SomeIP 消息
                let mut offset = 0;
                while offset + 16 <= data.len() {
                    let (_, header) = parse_someip_header(&data[offset..]).map_err(|e| {
                        SomeIPError::InvalidPacketFormat(format!("TCP SomeIP 头部解析失败: {}", e))
                    })?;
                    let msg_len = 16 + header.length as usize;
                    if offset + msg_len > data.len() {
                        break;
                    }

                    let payload = data[offset + 16..offset + msg_len].to_vec();
                    let msg = create_someip_message(
                        &raw_packet.timestamp,
                        &src_ip,
                        &dst_ip,
                        tcp.src_port,
                        tcp.dst_port,
                        header,
                        payload,
                    );
                    handle_someip_message(msg, session_manager, messages)?;
                    offset += msg_len;
                }
            }
        }
    }

    Ok(())
}

/// 从 SD 包中学习端口信息
fn learn_ports_from_sd(sd_packet: &SDPacket, known_ports: &mut std::collections::HashSet<u16>) {
    for option in &sd_packet.options {
        use parser::someip::sd_parser::SDOption::*;
        match option {
            Ipv4Endpoint(opt) => {
                known_ports.insert(opt.port);
            }
            Ipv4Multicast(opt) => {
                known_ports.insert(opt.port);
            }
            Ipv4SDEndpoint(opt) => {
                known_ports.insert(opt.port);
            }
            Ipv6Endpoint(opt) => {
                known_ports.insert(opt.port);
            }
            Ipv6Multicast(opt) => {
                known_ports.insert(opt.port);
            }
            Ipv6SDEndpoint(opt) => {
                known_ports.insert(opt.port);
            }
            _ => {}
        }
    }
}

/// 创建 SomeIP 消息结构
fn create_someip_message(
    timestamp: &SystemTime,
    src_ip: &str,
    dst_ip: &str,
    src_port: u16,
    dst_port: u16,
    header: parser::someip::header::SomeIPHeader,
    payload: Vec<u8>,
) -> SomeIPMessage {
    SomeIPMessage {
        timestamp: *timestamp,
        header,
        payload,
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        src_port,
        dst_port,
    }
}

/// 处理 SomeIP 消息（区分请求/响应并关联会话）
fn handle_someip_message(
    msg: SomeIPMessage,
    session_manager: &mut SessionManager,
    messages: &mut Vec<SomeIPMessage>,
) -> Result<()> {
    match msg.header.message_type {
        // 处理请求类型消息
        parser::someip::header::MessageType::Request
        | parser::someip::header::MessageType::RequestNoReturn => {
            session_manager.add_request(msg.clone())?;
        }
        // 处理响应类型消息
        parser::someip::header::MessageType::Response
        | parser::someip::header::MessageType::Error => {
            if let Some(pair) = session_manager.add_response(msg.clone())? {
                messages.push(pair.request);
                messages.push(msg.clone());
            }
        }
        // 处理单向消息（通知等）
        _ => {
            messages.push(msg.clone());
        }
    }
    Ok(())
}

/// 初始化日志系统
fn init_logger(verbose: u8) {
    let log_level = match verbose {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    env_logger::Builder::new()
        .filter(None, log_level)
        .format(|buf, record| {
            writeln!(
                buf,
                "[{}] [{}] {}",
                buf.timestamp_millis(),
                record.level(),
                record.args()
            )
        })
        .init();
}
