// src/parser/someip/matrix.rs
use crate::error::{Result, SomeIPError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatrixFile {
    #[serde(rename = "AR-PACKAGES")]
    pub ar_packages: Vec<ArPackage>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArPackage {
    #[serde(rename = "SHORT-NAME")]
    pub short_name: String,

    #[serde(rename = "ELEMENTS")]
    #[serde(default)]
    pub elements: Vec<Element>,

    #[serde(rename = "SUB-PACKAGES")]
    #[serde(default)]
    pub sub_packages: Vec<ArPackage>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Element {
    #[serde(rename = "SHORT-NAME")]
    pub short_name: String,

    #[serde(rename = "SOMEIP-SERVICE-INSTANCE")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_instance: Option<ServiceInstance>,

    #[serde(rename = "SOMEIP-SERVICE-INTERFACE")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_interface: Option<ServiceInterface>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceInstance {
    #[serde(rename = "SERVICE-REF")]
    pub service_ref: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceInterface {
    #[serde(rename = "SHORT-NAME")]
    pub short_name: String,

    #[serde(rename = "SOMEIP-SERVICE-ID")]
    pub service_id: Option<String>,

    #[serde(rename = "SOMEIP-EVENTS")]
    #[serde(default)]
    pub events: Vec<Event>,

    #[serde(rename = "SOMEIP-METHODS")]
    #[serde(default)]
    pub methods: Vec<Method>,

    #[serde(rename = "SOMEIP-FIELDS")]
    #[serde(default)]
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Event {
    #[serde(rename = "SHORT-NAME")]
    pub short_name: String,

    #[serde(rename = "SOMEIP-EVENT-ID")]
    pub event_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Method {
    #[serde(rename = "SHORT-NAME")]
    pub short_name: String,

    #[serde(rename = "SOMEIP-METHOD-ID")]
    pub method_id: String,

    #[serde(rename = "SOMEIP-METHOD-TYPE")]
    pub method_type: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Field {
    #[serde(rename = "SHORT-NAME")]
    pub short_name: String,

    #[serde(rename = "SOMEIP-FIELD-ID")]
    pub field_id: String,
}

pub struct Matrix {
    service_id_to_name: HashMap<u16, String>,
    method_id_to_name: HashMap<(u16, u16), String>,
    ip_to_name: HashMap<IpAddr, String>,
}

impl Matrix {
    pub fn new() -> Self {
        Self {
            service_id_to_name: HashMap::new(),
            method_id_to_name: HashMap::new(),
            ip_to_name: HashMap::new(),
        }
    }

    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // 尝试解析为JSON
        if let Ok(matrix) = serde_json::from_str::<MatrixFile>(&contents) {
            self.parse_xml_matrix(matrix);
            return Ok(());
        }

        // 尝试解析为YAML
        if let Ok(matrix) = serde_yaml::from_str::<MatrixFile>(&contents) {
            self.parse_xml_matrix(matrix);
            return Ok(());
        }

        Err(SomeIPError::MatrixFileError("Unsupported matrix file format".to_string()).into())
    }

    fn parse_xml_matrix(&mut self, matrix: MatrixFile) {
        // 解析服务和方法
        for package in &matrix.ar_packages {
            self.parse_package(package);
        }
    }

    fn parse_package(&mut self, package: &ArPackage) {
        // 解析服务接口
        for element in &package.elements {
            if let Some(service_interface) = &element.service_interface {
                if let Some(service_id_str) = &service_interface.service_id {
                    if let Ok(service_id) = u16::from_str_radix(service_id_str, 16) {
                        self.service_id_to_name
                            .insert(service_id, service_interface.short_name.clone());

                        // 解析方法
                        for method in &service_interface.methods {
                            if let Ok(method_id) = u16::from_str_radix(&method.method_id, 16) {
                                self.method_id_to_name
                                    .insert((service_id, method_id), method.short_name.clone());
                            }
                        }

                        // 解析事件
                        for event in &service_interface.events {
                            if let Ok(event_id) = u16::from_str_radix(&event.event_id, 16) {
                                self.method_id_to_name
                                    .insert((service_id, event_id), event.short_name.clone());
                            }
                        }

                        // 解析字段
                        for field in &service_interface.fields {
                            if let Ok(field_id) = u16::from_str_radix(&field.field_id, 16) {
                                // 字段有GET、SET和NOTIFIER方法
                                self.method_id_to_name.insert(
                                    (service_id, field_id),
                                    format!("{}_GET", field.short_name),
                                );
                                self.method_id_to_name.insert(
                                    (service_id, field_id | 0x8000),
                                    format!("{}_SET", field.short_name),
                                );
                                self.method_id_to_name.insert(
                                    (service_id, field_id | 0x4000),
                                    format!("{}_NOTIFIER", field.short_name),
                                );
                            }
                        }
                    }
                }
            }
        }

        // 递归解析子包
        for sub_package in &package.sub_packages {
            self.parse_package(sub_package);
        }
    }

    pub fn add_ip_mapping(&mut self, ip: &IpAddr, name: &str) {
        self.ip_to_name.insert(*ip, name.to_string());
    }

    pub fn get_service_name(&self, service_id: u16) -> Option<&str> {
        self.service_id_to_name.get(&service_id).map(|s| s.as_str())
    }

    pub fn get_method_name(&self, service_id: u16, method_id: u16) -> Option<&str> {
        self.method_id_to_name
            .get(&(service_id, method_id))
            .map(|s| s.as_str())
    }

    pub fn get_ip_name(&self, ip: &IpAddr) -> Option<&str> {
        self.ip_to_name.get(ip).map(|s| s.as_str())
    }
}
