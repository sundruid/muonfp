use std::process::Command;
use log::{info, error, debug};

pub struct IPBlocker;

impl IPBlocker {
    pub fn block_ip(ip_address: String) {
        debug!("Attempting to block IP: {}", ip_address);
        if Self::block_ip_now(&ip_address) {
            info!("IP {} blocked successfully.", ip_address);
        } else {
            error!("Failed to block IP {}", ip_address);
        }
    }

    fn block_ip_now(ip_address: &str) -> bool {
        let output = Command::new("nft")
            .arg("add")
            .arg("rule")
            .arg("inet")
            .arg("filter")
            .arg("input")
            .arg("ip")
            .arg("saddr")
            .arg(ip_address)
            .arg("drop")
            .output()
            .expect("Failed to execute nft command");

        if output.status.success() {
            info!("Command executed successfully.");
            debug!("Command output: {}", String::from_utf8_lossy(&output.stdout));
        } else {
            error!("Command failed with status: {}", output.status);
            error!("Error output: {}", String::from_utf8_lossy(&output.stderr));
        }

        output.status.success()
    }
}