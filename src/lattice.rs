use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Integrity taint level (ordered join-semilattice):
/// `Trusted ⊑ Internal ⊑ Untrusted ⊑ Adversarial`
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Integrity {
    /// Explicitly trusted input (e.g. direct user prompt, signed local config)
    Trusted = 0,
    /// Local workspace source code or internal repository data
    Internal = 1,
    /// External, unverified data (web pages, emails, GitHub issues, third-party APIs)
    Untrusted = 2,
    /// Data flagged with active prompt-injection / adversarial indicators
    Adversarial = 3,
}

impl fmt::Display for Integrity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Integrity::Trusted => write!(f, "Trusted"),
            Integrity::Internal => write!(f, "Internal"),
            Integrity::Untrusted => write!(f, "Untrusted"),
            Integrity::Adversarial => write!(f, "Adversarial"),
        }
    }
}

/// Confidentiality classification (powerset lattice):
/// A piece of data can carry multiple confidentiality tags simultaneously.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidentiality {
    Public,
    Internal,
    Secret,
}

impl fmt::Display for Confidentiality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Confidentiality::Public => write!(f, "Public"),
            Confidentiality::Internal => write!(f, "Internal"),
            Confidentiality::Secret => write!(f, "Secret"),
        }
    }
}

/// Element of the product security lattice `L = Integrity × P(Confidentiality)`,
/// augmented with provenance sources for explainable policy violations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityLabel {
    pub integrity: Integrity,
    pub confidentiality: BTreeSet<Confidentiality>,
    pub provenance: BTreeSet<String>,
}

impl SecurityLabel {
    pub fn bottom() -> Self {
        Self {
            integrity: Integrity::Trusted,
            confidentiality: BTreeSet::new(),
            provenance: BTreeSet::new(),
        }
    }

    pub fn new(integrity: Integrity, conf: Confidentiality, source: impl Into<String>) -> Self {
        let mut confidentiality = BTreeSet::new();
        if conf != Confidentiality::Public {
            confidentiality.insert(conf);
        }
        let mut provenance = BTreeSet::new();
        provenance.insert(source.into());
        Self {
            integrity,
            confidentiality,
            provenance,
        }
    }

    /// Least upper bound (join `⊔`) in the product lattice.
    /// Integrity takes `max`; Confidentiality and Provenance take set union.
    pub fn join(&self, other: &Self) -> Self {
        let integrity = self.integrity.max(other.integrity);
        let confidentiality = self
            .confidentiality
            .union(&other.confidentiality)
            .copied()
            .collect();
        let provenance = self
            .provenance
            .union(&other.provenance)
            .cloned()
            .collect();
        Self {
            integrity,
            confidentiality,
            provenance,
        }
    }

    pub fn is_secret(&self) -> bool {
        self.confidentiality.contains(&Confidentiality::Secret)
    }
}

impl fmt::Display for SecurityLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let conf_str = if self.confidentiality.is_empty() {
            "Public".to_string()
        } else {
            self.confidentiality
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join("+")
        };
        write!(f, "({}, {})", self.integrity, conf_str)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    /// Integrity violation: untrusted/adversarial data flowing into a privileged sink
    IntegrityViolation,
    /// Confidentiality violation: secret/internal data exfiltrated to an external sink
    ConfidentialityViolation,
    /// Implicit control-flow violation: session is tainted by untrusted data
    ImplicitFlowViolation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub kind: ViolationKind,
    pub tool: String,
    pub reason: String,
    pub label: SecurityLabel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum FlowDecision {
    Allow {
        effective_label: SecurityLabel,
    },
    Deny {
        violation: PolicyViolation,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lattice_join_is_commutative_and_monotonic() {
        let a = SecurityLabel::new(Integrity::Internal, Confidentiality::Secret, "read_file:.env");
        let b = SecurityLabel::new(
            Integrity::Untrusted,
            Confidentiality::Public,
            "fetch_url:github.com",
        );

        let ab = a.join(&b);
        let ba = b.join(&a);
        assert_eq!(ab, ba);
        assert_eq!(ab.integrity, Integrity::Untrusted);
        assert!(ab.is_secret());
        assert_eq!(ab.provenance.len(), 2);
    }
}
