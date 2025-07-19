// src/utils/timestamp.rs
use chrono::{DateTime, TimeZone, Utc};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn system_time_to_utc(time: SystemTime) -> DateTime<Utc> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    Utc.timestamp_opt(duration.as_secs() as i64, duration.subsec_nanos())
        .unwrap()
}

pub fn format_timestamp(time: &SystemTime) -> String {
    let utc = system_time_to_utc(*time);
    utc.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

pub fn format_duration_ms(duration: std::time::Duration) -> String {
    format!("{:.3}ms", duration.as_secs_f64() * 1000.0)
}
