use crate::lattice::FlowDecision;
use crate::policy::PolicyConfig;
use crate::tracker::TaintTracker;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

struct PendingCall {
    tool: String,
    args_json: String,
}

/// Runs a transparent stdio JSON-RPC 2.0 MCP proxy in front of an upstream MCP server.
/// Every `tools/call` is checked against the IFC lattice before forwarding, and every
/// response updates the session taint state.
pub fn run_mcp_proxy(
    policy: PolicyConfig,
    upstream_cmd: &[String],
    audit_log_path: Option<PathBuf>,
) -> Result<(), String> {
    if upstream_cmd.is_empty() {
        return Err("No upstream MCP server command specified after `--`".to_string());
    }

    let mut child = Command::new(&upstream_cmd[0])
        .args(&upstream_cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("Failed to spawn upstream MCP server `{}`: {}", upstream_cmd[0], e))?;

    let mut child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| "Failed to open upstream stdin".to_string())?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Failed to open upstream stdout".to_string())?;

    let tracker = Arc::new(Mutex::new(TaintTracker::new(policy)));
    let pending: Arc<Mutex<HashMap<String, PendingCall>>> = Arc::new(Mutex::new(HashMap::new()));
    let client_stdout = Arc::new(Mutex::new(io::stdout()));

    // Thread 1: Upstream MCP server stdout -> observe tool outputs -> client stdout
    let tracker_out = Arc::clone(&tracker);
    let pending_out = Arc::clone(&pending);
    let client_stdout_out = Arc::clone(&client_stdout);
    let audit_out = audit_log_path.clone();

    let reader_handle = thread::spawn(move || {
        let reader = BufReader::new(child_stdout);
        for line_res in reader.lines() {
            let Ok(line) = line_res else { break };
            if line.trim().is_empty() {
                continue;
            }

            if let Ok(val) = serde_json::from_str::<Value>(&line) {
                if let Some(id_val) = val.get("id") {
                    let id_key = id_val.to_string();
                    let matched_call = pending_out.lock().unwrap().remove(&id_key);
                    if let Some(call) = matched_call {
                        if let Some(result) = val.get("result") {
                            let output_text = result.to_string();
                            let mut guard = tracker_out.lock().unwrap();
                            let label =
                                guard.observe_tool_output(&call.tool, &call.args_json, &output_text);
                            eprintln!(
                                "[taintguard] observed {} -> label {} (ambient: {})",
                                call.tool,
                                label,
                                guard.ambient_label()
                            );
                            if let Some(ref p) = audit_out {
                                append_latest_audit(p, &guard);
                            }
                        }
                    }
                }
            }

            let mut out = client_stdout_out.lock().unwrap();
            let _ = writeln!(out, "{}", line);
            let _ = out.flush();
        }
    });

    // Main thread: Client stdin -> evaluate tools/call -> upstream stdin (or deny immediately)
    let stdin = io::stdin();
    for line_res in stdin.lock().lines() {
        let Ok(line) = line_res else { break };
        if line.trim().is_empty() {
            continue;
        }

        if let Ok(val) = serde_json::from_str::<Value>(&line) {
            let is_tool_call = val
                .get("method")
                .and_then(|m| m.as_str())
                .is_some_and(|m| m == "tools/call");

            if is_tool_call {
                let tool_name = val
                    .pointer("/params/name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let args_json = val
                    .pointer("/params/arguments")
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "{}".to_string());

                let decision = {
                    let mut guard = tracker.lock().unwrap();
                    let d = guard.evaluate_tool_call(tool_name, &args_json);
                    if let Some(ref p) = audit_log_path {
                        append_latest_audit(p, &guard);
                    }
                    d
                };

                match decision {
                    FlowDecision::Allow { effective_label } => {
                        eprintln!(
                            "[taintguard] ALLOW tools/call `{}` (label: {})",
                            tool_name, effective_label
                        );
                        if let Some(id_val) = val.get("id") {
                            pending.lock().unwrap().insert(
                                id_val.to_string(),
                                PendingCall {
                                    tool: tool_name.to_string(),
                                    args_json,
                                },
                            );
                        }
                    }
                    FlowDecision::Deny { violation } => {
                        eprintln!("[taintguard] BLOCKED `{}`: {}", tool_name, violation.reason);
                        let err_resp = json!({
                            "jsonrpc": "2.0",
                            "id": val.get("id").cloned().unwrap_or(Value::Null),
                            "error": {
                                "code": -32001,
                                "message": format!("TaintGuard IFC Violation: {}", violation.reason),
                                "data": violation
                            }
                        });
                        let mut out = client_stdout.lock().unwrap();
                        let _ = writeln!(out, "{}", err_resp);
                        let _ = out.flush();
                        continue;
                    }
                }
            }
        }

        if writeln!(child_stdin, "{}", line).is_err() || child_stdin.flush().is_err() {
            break;
        }
    }

    drop(child_stdin);
    let _ = reader_handle.join();
    let _ = child.wait();
    Ok(())
}

fn append_latest_audit(path: &PathBuf, tracker: &TaintTracker) {
    if let Some(last) = tracker.audit_log().last() {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            if let Ok(json_line) = serde_json::to_string(last) {
                let _ = writeln!(f, "{}", json_line);
            }
        }
    }
}
