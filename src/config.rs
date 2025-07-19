use clap::Parser;
use std::path::PathBuf;

/// SomeIP 协议解析工具，用于从 PCAP 文件中提取和分析 SomeIP 数据包
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Config {
    /// 要解析的 PCAP 文件路径
    #[arg(short, long, required = true)]
    pub pcap_file: PathBuf,

    /// 矩阵文件（ARXML/JSON/YAML）路径，用于将 ID 映射为名称
    #[arg(short, long)]
    pub matrix_file: Option<PathBuf>,

    /// SomeIP-SD 服务发现端口（默认：30490）
    #[arg(short, long, default_value_t = 30490)]
    pub sd_port: u16,

    /// 过滤特定 VLAN ID 的数据包（可选）
    #[arg(short, long)]
    pub vlan: Option<u16>,

    /// 输出格式（支持：text、json、yaml，默认：text）
    #[arg(short, long, default_value_t = String::from("text"))]
    pub output_format: String,

    /// 输出文件路径（默认：标准输出）
    #[arg(short, long)]
    pub output_file: Option<PathBuf>,

    /// 启用 verbose 模式（显示详细日志）
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// 请求超时时间（秒，默认：5）
    #[arg(long, default_value_t = 5)]
    pub request_timeout: u64,

    /// TP 分段重组超时时间（秒，默认：30）
    #[arg(long, default_value_t = 30)]
    pub tp_timeout: u64,

    /// TCP 连接超时时间（秒，默认：60）
    #[arg(long, default_value_t = 60)]
    pub tcp_timeout: u64,
}

/// 验证命令行参数合法性
impl Config {
    pub fn validate(&self) -> anyhow::Result<()> {
        // 检查 PCAP 文件是否存在
        if !self.pcap_file.exists() {
            anyhow::bail!("PCAP 文件不存在: {}", self.pcap_file.display());
        }

        // 检查矩阵文件（如果提供）是否存在
        if let Some(matrix_path) = &self.matrix_file {
            if !matrix_path.exists() {
                anyhow::bail!("矩阵文件不存在: {}", matrix_path.display());
            }
        }

        // 检查输出格式是否合法
        match self.output_format.as_str() {
            "text" | "json" | "yaml" => Ok(()),
            _ => anyhow::bail!("不支持的输出格式: {}", self.output_format),
        }
    }
}
