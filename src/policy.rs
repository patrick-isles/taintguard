use crate::lattice::{Confidentiality, Integrity};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementMode {
    /// Block policy violations immediately before tool execution
    Strict,
    /// Log violations to audit trail but allow execution
    Audit,
}

impl Default for EnforcementMode {
    fn default() -> Self {
        EnforcementMode::Strict
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRule {
    /// Regex matching the MCP tool name (e.g. "^(fetch_url|web_search|read_email)$")
    pub tool_pattern: String,
    /// Optional regex matching serialized JSON arguments (e.g. "\\.env|\\.ssh|id_rsa")
    #[serde(default)]
    pub arg_pattern: Option<String>,
    pub integrity: Integrity,
    pub confidentiality: Confidentiality,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkRule {
    /// Regex matching the MCP tool name (e.g. "^(run_command|bash|exec|shell)$")
    pub tool_pattern: String,
    /// Maximum integrity taint level allowed to reach this sink
    pub max_integrity: Integrity,
    /// Confidentiality tags forbidden from reaching this sink
    #[serde(default)]
    pub forbid_confidentiality: Vec<Confidentiality>,
    /// Whether ambient (implicit control-flow) session taint also triggers this sink rule
    #[serde(default = "default_true")]
    pub enforce_implicit_flow: bool,
    #[serde(default)]
    pub description: String,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub mode: EnforcementMode,
    #[serde(default = "default_true")]
    pub detect_secrets: bool,
    #[serde(default = "default_true")]
    pub detect_prompt_injection: bool,
    #[serde(default)]
    pub sources: Vec<SourceRule>,
    #[serde(default)]
    pub sinks: Vec<SinkRule>,
}

pub const DEFAULT_POLICY_TOML: &str = r#"# taintguard.toml — Information-Flow Control Policy for MCP Agents
# Integrity lattice:       trusted ⊑ internal ⊑ untrusted ⊑ adversarial
# Confidentiality lattice: public ⊑ internal ⊑ secret

mode = "strict"
detect_secrets = true
detect_prompt_injection = true

# --- TAINT SOURCES (what labels tool outputs introduce into the session) ---

[[sources]]
tool_pattern = "(?i)(read_file|view_file|cat|get_file|read_secret)"
arg_pattern = "(?i)(\\.env|\\.ssh|id_rsa|id_ed25519|credentials|secrets?\\.|token|key\\.pem)"
integrity = "internal"
confidentiality = "secret"
description = "Sensitive local credential/secret files"

[[sources]]
tool_pattern = "(?i)(fetch|http|curl|browse|web|scrape|search_web|read_email|gmail|slack|github_issue|get_issue|get_pr)"
integrity = "untrusted"
confidentiality = "public"
description = "External untrusted network/communication sources"

[[sources]]
tool_pattern = "(?i)(read_file|view_file|list_dir|grep|search_code|git_diff)"
integrity = "internal"
confidentiality = "internal"
description = "Local workspace source files"

# --- PRIVILEGED SINKS (what labels are allowed to reach dangerous tools) ---

[[sinks]]
tool_pattern = "(?i)(bash|shell|exec|run_command|terminal|spawn|eval)"
max_integrity = "internal"
forbid_confidentiality = ["secret"]
enforce_implicit_flow = true
description = "Arbitrary command execution sink (blocks untrusted control-flow & secret leakage)"

[[sinks]]
tool_pattern = "(?i)(http_post|http_put|fetch|curl|webhook|send_email|post_message|slack_post|create_issue)"
max_integrity = "untrusted"
forbid_confidentiality = ["secret"]
enforce_implicit_flow = false
description = "Outbound network/messaging sink (prevents secret exfiltration)"

[[sinks]]
tool_pattern = "(?i)(write_file|edit_file|delete_file|rm|patch)"
max_integrity = "internal"
forbid_confidentiality = []
enforce_implicit_flow = true
description = "Filesystem mutation sink (blocks untrusted indirect prompt injection writes)"
"#;

impl PolicyConfig {
    pub fn default_policy() -> Self {
        toml::from_str(DEFAULT_POLICY_TOML).expect("built-in default policy must parse")
    }

    pub fn from_file(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read policy file {}: {}", path.display(), e))?;
        toml::from_str(&raw)
            .map_err(|e| format!("Failed to parse TOML policy {}: {}", path.display(), e))
    }

    pub fn match_source(&self, tool: &str, args_json: &str) -> Option<&SourceRule> {
        for rule in &self.sources {
            let tool_re = Regex::new(&rule.tool_pattern).ok()?;
            if !tool_re.is_match(tool) {
                continue;
            }
            if let Some(arg_pat) = &rule.arg_pattern {
                let arg_re = Regex::new(arg_pat).ok()?;
                if !arg_re.is_match(args_json) {
                    continue;
                }
            }
            return Some(rule);
        }
        None
    }

    pub fn match_sink(&self, tool: &str) -> Option<&SinkRule> {
        for rule in &self.sinks {
            if let Ok(re) = Regex::new(&rule.tool_pattern) {
                if re.is_match(tool) {
                    return Some(rule);
                }
            }
        }
        None
    }
}
