//! The disco checks, against a real Tailscale client.
//!
//! Nothing here can be answered by our own code. A disco message is sealed in a
//! NaCl box, so it either opens on the other side or the exchange is silent —
//! there is no partial credit and no error message to interpret. The first
//! version of `ts-disco` appended the Poly1305 tag the way every other AEAD in
//! this project does, sealed and opened perfectly against itself, and was
//! rejected by `tailscaled` with "failed to open naclbox (wrong rcpt?)". NaCl
//! puts the tag first.
//!
//! So the reference client is the oracle, in both directions: it must answer our
//! probe, and it must accept our answer to its own.

use std::process::Command;
use std::sync::OnceLock;

use serde_json::Value;

use crate::harness::{NOT_BUILT, Run};
use crate::{Env, Status, Target};

/// How long the harness listens, and when the reference client is nudged into
/// probing us.
const LISTEN_SECONDS: u64 = 20;
const TRIGGER_AFTER_SECONDS: u64 = 8;

/// Where the lab's reference client listens.
fn socket_path(env: &Env) -> std::path::PathBuf {
    env.vectors
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(std::path::Path::new("."))
        .join(".lab/tailscaled.sock")
}

/// One disco session: our probes, and the reference client's.
fn session(env: &Env) -> &'static Result<Run, String> {
    static SESSION: OnceLock<Result<Run, String>> = OnceLock::new();
    SESSION.get_or_init(|| start(env))
}

fn start(env: &Env) -> Result<Run, String> {
    let Some(harness) = &env.harness else {
        return Err(NOT_BUILT.into());
    };
    if env.target == Target::TailscaleSaas {
        return Err("the hosted service is HTTPS-only and there is no TLS client yet".into());
    }
    let (Some((host, port)), Some(auth_key)) = (&env.control_address, &env.preauth_key) else {
        return Err("no lab; start one with tests/lab/lab.sh up".into());
    };

    let socket = socket_path(env);
    if !socket.exists() {
        return Err(
            "no reference client; start one with tests/lab/lab.sh reference — disco cannot \
             be checked against our own code"
                .into(),
        );
    }

    let state = harness.scratch("disco");
    let state = state.to_string_lossy().into_owned();
    let port = port.to_string();

    let registered = harness.run(&["register", &state, host, &port, auth_key])?;
    let Some(node_key) = registered
        .event("registered")
        .and_then(|e| e["node"].as_str())
    else {
        return Err(format!("could not register: {}", registered.tail()));
    };

    // The reference client only probes a peer it is trying to reach, so it has
    // to be given a reason. Its own address for us comes from the netmap, which
    // means asking the server what address we were given.
    let address = tailnet_address(node_key)?;

    // The harness listens while a nudge is delivered partway through.
    let seconds = LISTEN_SECONDS.to_string();
    let child = Command::new(harness.path())
        .args(["disco", &state, host, &port, &seconds])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start the harness: {e}"))?;

    std::thread::sleep(std::time::Duration::from_secs(TRIGGER_AFTER_SECONDS));
    // `--until-direct=false` because the tunnel itself is not up: what is being
    // checked is the path discovery, not the traffic that would follow it.
    let nudge = Command::new("sudo")
        .args([
            "-n",
            "tailscale",
            &format!("--socket={}", socket.display()),
            "ping",
            "--c",
            "3",
            "--until-direct=false",
            &address,
        ])
        .output();

    let output = child
        .wait_with_output()
        .map_err(|e| format!("the harness did not finish: {e}"))?;

    let mut run = Run::from_output(&output);
    if let Ok(nudge) = nudge {
        run.note = String::from_utf8_lossy(&nudge.stdout).into_owned();
    }
    Ok(run)
}

/// The tailnet address the server gave a node key.
fn tailnet_address(node_key: &str) -> Result<String, String> {
    let nodes = crate::headscale::nodes()?;
    let node = crate::headscale::find_by_node_key(&nodes, node_key)
        .ok_or("the registered node is absent from the server")?;
    node.addresses
        .iter()
        .find(|address| address.contains('.'))
        .cloned()
        .ok_or_else(|| "the node has no IPv4 tailnet address".into())
}

fn with_session(env: &Env, f: impl FnOnce(&Run) -> Status) -> Status {
    match session(env) {
        Ok(run) => f(run),
        Err(reason) => Status::Skip(reason.clone()),
    }
}

/// We probe, and a real client answers.
pub fn ping(env: &Env) -> Status {
    with_session(env, |run| {
        let pongs = run
            .event("disco")
            .and_then(|e| e["pongs"].as_u64())
            .unwrap_or(0);
        if pongs == 0 {
            return Status::Fail(format!(
                "no pong from the reference client, so it could not open our box: {}",
                run.tail()
            ));
        }
        let Some(pong) = run.event("pong") else {
            return Status::Fail("a pong was counted but not reported".into());
        };
        if pong["txid_matches"] != Value::Bool(true) {
            return Status::Fail(
                "the pong did not echo our transaction id, so it cannot be attributed to \
                 the probe — or to the path the probe took"
                    .into(),
            );
        }
        Status::Pass(format!(
            "a real tailscaled opened our NaCl box and answered: it sees us at {}, and \
             echoed the transaction id that ties the answer to the path. The box is \
             unforgeable, so this is the whole format — magic, key, nonce, and NaCl's \
             tag-before-ciphertext layout — verified at once.",
            pong["observed"].as_str().unwrap_or("(unreported)")
        ))
    })
}

/// A real client probes us, and accepts our answer.
pub fn pong(env: &Env) -> Status {
    with_session(env, |run| {
        let pings = run
            .event("disco")
            .and_then(|e| e["pings"].as_u64())
            .unwrap_or(0);
        if pings == 0 {
            return Status::Fail(format!(
                "the reference client never probed us, so our pong was not exercised: {}",
                run.tail()
            ));
        }

        // Our own count says we answered. That it was *accepted* is the
        // reference client's to report: `tailscale ping` prints a pong line
        // only when it got a valid one back.
        let accepted = run.note.contains("pong from");
        if !accepted {
            return Status::Fail(format!(
                "we answered {pings} ping(s) but the reference client did not report a \
                 valid pong: {}",
                run.note.trim()
            ));
        }
        Status::Pass(format!(
            "the reference client probed us on the shared socket and accepted our answer: \
             {}. Its own words, not ours — a pong it could not open would simply be \
             silence.",
            run.note
                .lines()
                .find(|line| line.contains("pong from"))
                .unwrap_or("")
                .trim()
        ))
    })
}

/// Our endpoints reach the server, and peers use them.
pub fn endpoints(env: &Env) -> Status {
    with_session(env, |run| {
        let Some(advertised) = run
            .event("endpoint")
            .and_then(|e| e["advertised"].as_str())
        else {
            return Status::Fail(format!("no endpoint was advertised: {}", run.tail()));
        };
        if advertised.starts_with("127.") || advertised.starts_with("0.0.0.0") {
            return Status::Fail(format!(
                "advertised {advertised}, which no peer on another machine can reach"
            ));
        }

        // The proof is not that we sent it, but that a peer used it. The
        // reference client had no other way to learn where to probe.
        let pings = run
            .event("disco")
            .and_then(|e| e["pings"].as_u64())
            .unwrap_or(0);
        if pings == 0 {
            return Status::Fail(format!(
                "advertised {advertised} but nothing arrived there, so the server \
                 either did not accept the endpoint or did not pass it on"
            ));
        }

        let observed = run
            .event("pong")
            .and_then(|e| e["observed"].as_str())
            .unwrap_or("");
        Status::Pass(format!(
            "advertised {advertised} in the MapRequest, and the reference client — which \
             had no other source for it — probed us there. Its pong reports seeing us at \
             {observed}. No STUN: this is the address on our side of any NAT, which is \
             enough on a LAN and is what the pong's observed address exists to correct."
        ))
    })
}
