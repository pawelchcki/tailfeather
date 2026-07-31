//! Asking the control server what it thinks happened.
//!
//! A check that only reads our own output proves we sent something, not that it
//! was understood. `headscale nodes list` is the server's own view, and it is
//! what makes "the node registered" a claim about the server rather than about
//! us.

use std::process::Command;

/// The lab container, started by `tests/lab/lab.sh up`.
const CONTAINER: &str = "headscale-lab";

/// One row of `headscale nodes list`.
#[derive(Debug, Clone)]
pub struct Node {
    pub id: u64,
    pub name: String,
    pub node_key: String,
    pub machine_key: String,
    pub addresses: Vec<String>,
}

/// Every node the server knows about.
///
/// `Err` means the question could not be asked — the container is not running,
/// or `podman` is absent — which callers must report as a skip. A check that
/// failed because the lab was down would make the suite unsafe to gate on.
pub fn nodes() -> Result<Vec<Node>, String> {
    let output = Command::new("podman")
        .args([
            "exec",
            CONTAINER,
            "headscale",
            "nodes",
            "list",
            "--output",
            "json",
        ])
        .output()
        .map_err(|e| format!("could not run podman: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "headscale nodes list failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("headscale nodes list is not JSON: {e}"))?;
    let rows = parsed
        .as_array()
        .ok_or("headscale nodes list is not an array")?;

    Ok(rows
        .iter()
        .map(|row| Node {
            id: row["id"].as_u64().unwrap_or(0),
            name: row["name"].as_str().unwrap_or_default().to_string(),
            node_key: row["node_key"].as_str().unwrap_or_default().to_string(),
            machine_key: row["machine_key"].as_str().unwrap_or_default().to_string(),
            addresses: row["ip_addresses"]
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect())
}

/// The node holding a given node key, if the server has one.
pub fn find_by_node_key<'a>(nodes: &'a [Node], node_key: &str) -> Option<&'a Node> {
    nodes.iter().find(|n| n.node_key == node_key)
}
