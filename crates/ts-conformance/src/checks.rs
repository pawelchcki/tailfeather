//! The enumeration of every behaviour a Tailscale-compatible node must exhibit.
//!
//! This list is the specification. Adding a behaviour here before implementing
//! it is deliberate: the score is meant to start low and rise, and a gap that
//! is not written down is a gap nobody is tracking.
//!
//! Checks that can be answered today are answered. The rest declare precisely
//! what is missing, so each one reads as the next piece of work rather than as
//! a vague intention.

use crate::{Area, Check, Env, Status, Target, http};

pub fn all() -> &'static [Check] {
    CHECKS
}

/// Fetch a URL from the configured control server, or explain why not.
fn control_get(env: &Env, path: &str) -> Result<http::Response, Status> {
    let Some(base) = &env.control_url else {
        return Err(Status::Skip(
            "no control server configured; start one with tests/lab/lab.sh up".into(),
        ));
    };
    if env.target == Target::TailscaleSaas {
        return Err(Status::Todo(
            "the hosted service is HTTPS-only and this suite has no TLS client yet".into(),
        ));
    }
    http::get(&format!("{base}{path}")).map_err(Status::Fail)
}

static CHECKS: &[Check] = &[
    // ---------------------------------------------------------------- data plane
    Check {
        id: "wg.handshake.responder",
        area: Area::DataPlane,
        description: "completes a WireGuard handshake as responder",
        run: |_| {
            Status::External(
                "scripts/interop-wireguard.sh — real kernel WireGuard initiates and succeeds".into(),
            )
        },
    },
    Check {
        id: "wg.transport.roundtrip",
        area: Area::DataPlane,
        description: "encrypts and decrypts transport data",
        run: |_| Status::External("scripts/interop-wireguard.sh — in-tunnel ping answered".into()),
    },
    Check {
        id: "wg.replay",
        area: Area::DataPlane,
        description: "rejects replayed and out-of-window counters",
        run: |_| Status::External("wg-core unit tests, ladder verified against the kernel".into()),
    },
    Check {
        id: "wg.rekey",
        area: Area::DataPlane,
        description: "survives rekeying without dropping traffic",
        run: |_| {
            Status::External(
                "hardware soak: 300/300 packets across two rekeys at 120 s".into(),
            )
        },
    },
    Check {
        id: "wg.handshake.initiator",
        area: Area::DataPlane,
        description: "initiates a WireGuard handshake",
        run: |_| {
            Status::Todo(
                "wg-core is responder-only. A Tailscale node must initiate to its peers; \
                 the ladder is already proven in the test-only initiator"
                    .into(),
            )
        },
    },
    Check {
        id: "wg.multipeer",
        area: Area::DataPlane,
        description: "maintains sessions with many peers at once",
        run: |_| {
            Status::Todo(
                "Device is generic over PEERS but has only ever been exercised with one".into(),
            )
        },
    },
    // ---------------------------------------------------------------------- keys
    Check {
        id: "keys.machine",
        area: Area::Keys,
        description: "machine key: the identity the control plane knows",
        run: |_| Status::Todo("no machine key is generated or persisted".into()),
    },
    Check {
        id: "keys.node",
        area: Area::Keys,
        description: "node key: the WireGuard identity advertised in the netmap",
        run: |_| Status::Todo("the WireGuard key exists but is not tied to a node identity".into()),
    },
    Check {
        id: "keys.disco",
        area: Area::Keys,
        description: "disco key: used for path discovery",
        run: |_| Status::Todo("no disco key".into()),
    },
    Check {
        id: "keys.encoding",
        area: Area::Keys,
        description: "encodes keys in the wire form the server uses",
        run: |env| {
            // The server's own key is the one piece of key encoding we can
            // check without having implemented anything: whatever format it
            // publishes is the format we must both parse and emit.
            let key = match env.vector("server_key.json") {
                Ok(v) => v,
                Err(e) => return Status::Skip(e),
            };
            let Some(published) = key["key_at_minimum"]["publicKey"].as_str() else {
                return Status::Fail("no publicKey in the captured /key response".into());
            };
            let Some(hex) = published.strip_prefix("mkey:") else {
                return Status::Fail(format!("unexpected key prefix in {published}"));
            };
            if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Status::Fail(format!("not 32 bytes of hex: {published}"));
            }
            Status::Pass(format!(
                "server publishes 'mkey:' + 64 hex chars; parsed {}…",
                &hex[..16]
            ))
        },
    },
    Check {
        id: "keys.persistence",
        area: Area::Keys,
        description: "keys survive a reboot",
        run: |_| Status::Todo("nothing is written to NVS; a reboot would re-register".into()),
    },
    // ------------------------------------------------------------------ transport
    Check {
        id: "transport.tls",
        area: Area::Transport,
        description: "TLS 1.3 client, required by the hosted service",
        run: |_| {
            Status::Todo(
                "no TLS client. Headscale on a LAN accepts plain HTTP, but \
                 controlplane.tailscale.com does not, so this gates hosted support. \
                 embedded-tls is the candidate"
                    .into(),
            )
        },
    },
    Check {
        id: "transport.http2",
        area: Area::Transport,
        description: "HTTP/2 client over the Noise channel",
        run: |_| {
            Status::Todo(
                "no HTTP/2. HPACK's dynamic table is the sharp edge: it is stateful, so \
                 ignoring it desynchronises every subsequent header"
                    .into(),
            )
        },
    },
    // ---------------------------------------------------------------- control
    Check {
        id: "control.key.fetch",
        area: Area::Control,
        description: "fetches the server's Noise public key from /key",
        run: |env| {
            let response = match control_get(env, "/key?v=118") {
                Ok(r) => r,
                Err(status) => return status,
            };
            if response.status != 200 {
                return Status::Fail(format!("/key?v=118 returned {}", response.status));
            }
            let json: serde_json::Value = match serde_json::from_str(&response.body) {
                Ok(j) => j,
                Err(e) => return Status::Fail(format!("/key body is not JSON: {e}")),
            };
            match json["publicKey"].as_str() {
                Some(key) if key.starts_with("mkey:") => {
                    Status::Pass(format!("live server published {}…", &key[..21]))
                }
                _ => Status::Fail(format!("no usable publicKey in {}", response.body)),
            }
        },
    },
    Check {
        id: "control.key.capver",
        area: Area::Control,
        description: "sends a capability version the server still accepts",
        run: |env| {
            // Headscale rejects clients below a minimum version outright, so
            // this is a hard compatibility gate rather than a nicety.
            let response = match control_get(env, "/key") {
                Ok(r) => r,
                Err(status) => return status,
            };
            if response.body.contains("capability version must be set") {
                Status::Pass(
                    "server requires ?v=<capver>; our client must send one and track the minimum"
                        .into(),
                )
            } else {
                Status::Fail(format!(
                    "expected the server to demand a capability version, got: {}",
                    response.body.trim()
                ))
            }
        },
    },
    Check {
        id: "control.capver.minimum",
        area: Area::Control,
        description: "advertises a capability version at or above the server's floor",
        run: |env| {
            let key = match env.vector("server_key.json") {
                Ok(v) => v,
                Err(e) => return Status::Skip(e),
            };
            let Some(minimum) = key["minimum_capability_version"].as_u64() else {
                return Status::Skip("capability floor not probed; run tests/lab/capture.sh".into());
            };
            // Discovered by binary search against the live server rather than
            // read from documentation, because the floor rises as servers are
            // upgraded and a stale constant fails before any protocol runs.
            Status::Todo(format!(
                "no client to advertise one yet. This server rejects anything below v{minimum}"
            ))
        },
    },
    Check {
        id: "control.noise.handshake",
        area: Area::Control,
        description: "completes the ts2021 Noise IK handshake",
        run: |_| {
            Status::Todo(
                "no ts2021 client. Different handshake from WireGuard's (IK, not IKpsk2, \
                 over TCP) but every primitive is already in the tree"
                    .into(),
            )
        },
    },
    Check {
        id: "control.controlbase.framing",
        area: Area::Control,
        description: "speaks the controlbase framing over the Noise channel",
        run: |_| Status::Todo("not implemented".into()),
    },
    Check {
        id: "control.register",
        area: Area::Control,
        description: "registers with a preauth key and appears on the server",
        run: |_| {
            Status::Todo(
                "not implemented. The lab mints a key and the check will assert the node \
                 shows up in `headscale nodes list`"
                    .into(),
            )
        },
    },
    Check {
        id: "control.reauth",
        area: Area::Control,
        description: "re-registers when the node key expires",
        run: |_| Status::Todo("not implemented".into()),
    },
    Check {
        id: "control.hostinfo",
        area: Area::Control,
        description: "reports a Hostinfo the server accepts",
        run: |env| {
            let map = match env.vector("map_response.json") {
                Ok(v) => v,
                Err(e) => return Status::Skip(e),
            };
            // Ground truth for what a real client reports about itself. Our
            // Hostinfo has to be close enough that the server treats us as a
            // supported client, including a version at or above its minimum.
            let hostinfo = map
                .as_array()
                .and_then(|responses| responses.iter().find_map(|r| r["Node"]["Hostinfo"].as_object()));
            match hostinfo {
                Some(fields) => {
                    let mut names: Vec<&str> = fields.keys().map(String::as_str).collect();
                    names.sort();
                    Status::Todo(format!(
                        "not implemented. Reference client sends: {}",
                        names.join(", ")
                    ))
                }
                None => Status::Skip("captured map has no Node.Hostinfo".into()),
            }
        },
    },
    // ----------------------------------------------------------------- netmap
    Check {
        id: "netmap.fields",
        area: Area::Netmap,
        description: "handles every top-level MapResponse field the server sends",
        run: |env| {
            let map = match env.vector("map_response.json") {
                Ok(v) => v,
                Err(e) => return Status::Skip(e),
            };
            let Some(responses) = map.as_array() else {
                return Status::Fail("captured map is not an array".into());
            };
            let mut fields: Vec<&str> = responses
                .iter()
                .filter_map(|r| r.as_object())
                .flat_map(|o| o.keys().map(String::as_str))
                .collect();
            fields.sort();
            fields.dedup();
            Status::Todo(format!(
                "no parser yet. {} response(s) captured using: {}",
                responses.len(),
                fields.join(", ")
            ))
        },
    },
    Check {
        id: "netmap.delta",
        area: Area::Netmap,
        description: "applies incremental updates, not just full maps",
        run: |env| {
            let map = match env.vector("map_response.json") {
                Ok(v) => v,
                Err(e) => return Status::Skip(e),
            };
            // Deltas are the case a naive parser gets wrong: they omit fields
            // rather than repeating them, so treating every response as a full
            // map silently discards state.
            let deltas = map
                .as_array()
                .map(|responses| {
                    responses
                        .iter()
                        .filter(|r| {
                            r.get("PeersChanged").is_some()
                                || r.get("PeersChangedPatch").is_some()
                                || r.get("PeersRemoved").is_some()
                        })
                        .count()
                })
                .unwrap_or(0);
            Status::Todo(format!(
                "no parser yet. {deltas} of the captured responses are deltas, so this cannot \
                 be skipped"
            ))
        },
    },
    Check {
        id: "netmap.streaming",
        area: Area::Netmap,
        description: "parses the netmap without buffering it whole",
        run: |env| {
            let path = env.vectors.join("map_response.json");
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            Status::Todo(format!(
                "no parser yet. The captured map is {size} bytes for a two-node tailnet; \
                 a real one will not fit in RAM if buffered"
            ))
        },
    },
    Check {
        id: "netmap.compression",
        area: Area::Netmap,
        description: "handles the compression the server negotiates",
        run: |_| {
            Status::Todo(
                "not implemented. Tailscale compresses map responses with zstd; whether the \
                 server can be asked for uncompressed must be confirmed against both"
                    .into(),
            )
        },
    },
    Check {
        id: "netmap.to_peers",
        area: Area::Netmap,
        description: "configures WireGuard peers from the netmap",
        run: |_| Status::Todo("not implemented".into()),
    },
    // ------------------------------------------------------------------- DERP
    Check {
        id: "derp.map.parse",
        area: Area::Derp,
        description: "parses the DERP map",
        run: |env| {
            let map = match env.vector("map_response.json") {
                Ok(v) => v,
                Err(e) => return Status::Skip(e),
            };
            let regions = map
                .as_array()
                .and_then(|responses| {
                    responses
                        .iter()
                        .find_map(|r| r["DERPMap"]["Regions"].as_object())
                })
                .map(|r| r.len())
                .unwrap_or(0);
            if regions == 0 {
                return Status::Skip("captured map contains no DERP regions".into());
            }
            Status::Todo(format!(
                "no parser yet. The lab advertises {regions} region(s); the hosted service \
                 advertises dozens"
            ))
        },
    },
    Check {
        id: "derp.relay",
        area: Area::Derp,
        description: "relays through DERP when no direct path exists",
        run: |_| {
            Status::Todo(
                "not implemented. Skippable on a LAN where peers reach each other directly, \
                 but the hosted service depends on it"
                    .into(),
            )
        },
    },
    // ------------------------------------------------------------------ disco
    Check {
        id: "disco.pong",
        area: Area::Disco,
        description: "answers disco pings on the WireGuard socket",
        run: |_| {
            Status::Todo(
                "not implemented. Demultiplexed from WireGuard by the magic prefix on the \
                 shared UDP socket"
                    .into(),
            )
        },
    },
    Check {
        id: "disco.ping",
        area: Area::Disco,
        description: "probes peers to find a working path",
        run: |_| Status::Todo("not implemented".into()),
    },
    Check {
        id: "disco.endpoints",
        area: Area::Disco,
        description: "reports its own endpoints to the control plane",
        run: |_| Status::Todo("not implemented".into()),
    },
    // -------------------------------------------------------------- exit node
    Check {
        id: "exit.forward.udp",
        area: Area::ExitNode,
        description: "forwards UDP out of the uplink from its own address",
        run: |_| {
            Status::External(
                "scripts/bench-exit.sh — echo server observes the device's own address".into(),
            )
        },
    },
    Check {
        id: "exit.forward.tcp",
        area: Area::ExitNode,
        description: "forwards TCP, including TLS, out of the uplink",
        run: |_| {
            Status::External("scripts/test-http.sh — HTTP and HTTPS complete through the device".into())
        },
    },
    Check {
        id: "exit.advertise",
        area: Area::ExitNode,
        description: "advertises itself as an exit node",
        run: |_| {
            Status::Todo(
                "not implemented. Hostinfo.RoutableIPs = 0.0.0.0/0 and ::/0, then the \
                 server-side route approval"
                    .into(),
            )
        },
    },
];
