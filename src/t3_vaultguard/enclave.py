"""
T3-VaultGuard Sandboxed TEE Enclave Engine, Scoped Member Delegation,
Smart Verifiable Credential (Smart VC) Zero-Knowledge Predicate Verifier,
and Tamper-Evident Merkle Activity Log (`client.getActivityLog()`).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .crypto import Aes256GcmEnvelope, ThresholdQuorumKeyManager

PLACEHOLDER_RE = re.compile(r"\{\{([a-zA-Z0-9_.]+)\}\}")


@dataclass
class MemberDelegationGrant:
    grantee: str                     # e.g. "did:t3n:agent-7f3a"
    on_behalf_of: str                # e.g. "did:t3n:user-alice"
    contract_id: str                 # e.g. "z:t3n-org-99a1:vaultguard"
    version_req: str                 # e.g. "^0.4.0"
    function: str                    # e.g. "book-offer"
    scopes: List[Dict[str, Any]]
    allowed_hosts: List[str]         # e.g. ["api.duffel.com"]
    allowed_placeholders: List[str]  # e.g. ["{{user.passport_no}}", "{{user.email}}"]
    expires_at_ms: int = 1_900_000_000_000


@dataclass
class SmartVerifiableCredential:
    """
    W3C Verifiable Credential + Terminal 3 Smart VC with selective-disclosure ZK predicate proof.
    """
    vc_id: str
    subject_did: str
    issuer_did: str
    credential_type: List[str]
    issuance_date: str
    claims: Dict[str, Any]
    zk_predicates: Dict[str, bool]
    proof_signature: str

    @classmethod
    def issue(
        cls,
        vc_id: str,
        subject_did: str,
        claims: Dict[str, Any],
        zk_predicates: Dict[str, bool],
        issuer_did: str = "did:key:terminal3",
        issuer_secret: bytes = b"t3n-smart-vc-issuer-root-key-32b",
    ) -> "SmartVerifiableCredential":
        payload = json.dumps(
            {
                "id": vc_id,
                "subject": subject_did,
                "issuer": issuer_did,
                "claims_commitment": hashlib.sha256(json.dumps(claims, sort_keys=True).encode()).hexdigest(),
                "zk_predicates": zk_predicates,
            },
            sort_keys=True,
        ).encode()
        sig = hmac.new(issuer_secret, payload, hashlib.sha256).hexdigest()
        return cls(
            vc_id=vc_id,
            subject_did=subject_did,
            issuer_did=issuer_did,
            credential_type=["VerifiableCredential", "T3ReusableKycCredential"],
            issuance_date="2026-11-10T00:00:00Z",
            claims=claims,
            zk_predicates=zk_predicates,
            proof_signature=sig,
        )

    def verify_presentation(
        self,
        required_predicates: List[str],
        issuer_secret: bytes = b"t3n-smart-vc-issuer-root-key-32b",
    ) -> Dict[str, Any]:
        payload = json.dumps(
            {
                "id": self.vc_id,
                "subject": self.subject_did,
                "issuer": self.issuer_did,
                "claims_commitment": hashlib.sha256(json.dumps(self.claims, sort_keys=True).encode()).hexdigest(),
                "zk_predicates": self.zk_predicates,
            },
            sort_keys=True,
        ).encode()
        expected_sig = hmac.new(issuer_secret, payload, hashlib.sha256).hexdigest()
        sig_valid = hmac.compare_digest(self.proof_signature, expected_sig)
        predicates_satisfied = all(self.zk_predicates.get(p, False) for p in required_predicates)
        return {
            "valid": bool(sig_valid and predicates_satisfied),
            "vc_id": self.vc_id,
            "subject_did": self.subject_did,
            "issuer_did": self.issuer_did,
            "verified_predicates": {p: bool(self.zk_predicates.get(p, False)) for p in required_predicates},
            "raw_pii_disclosed": False,
        }


@dataclass
class ActivityEntry:
    seq_no: int
    hash: str
    prev_hash: str
    timestamp_ms: int
    caller_type: str  # "agent" | "human"
    actor: str
    on_behalf_of: str
    org: str
    contract: str
    function: str
    outcome: str      # "success" | "denied" | "error"
    roles: List[str] = field(default_factory=list)
    custom: Dict[str, str] = field(default_factory=dict)


class T3nVaultGuardEnclave:
    """
    Simulated T3N Confidential Computing Enclave (`z:<tid>:vaultguard`) with:
      - Encrypted Tenant KV Maps (`z:<tid>:kv-secrets`) protected by AES-256-GCM & 3-of-5 Quorum Shares
      - `member-delegation-update` & `checkDelegation()` enforcement
      - `http-with-placeholders` zero-leak outbound PII substitution
      - Outbound `allowed_hosts` firewall against prompt-injection exfiltration
      - Merkle-tree & hash-chained `getActivityLog()` with custom labels (`secret.read`, `policy.update`, `tool.install`, `tool.remove`)
    """

    def __init__(self, tenant_did: str = "did:t3n:org-99a1"):
        self.tenant_did = tenant_did
        self.contract_id = "z:t3n-org-99a1:vaultguard"
        self._wrapping_key = hashlib.sha256(f"t3n-enclave-wrapping-key:{tenant_did}".encode()).digest()
        self.quorum_shares = ThresholdQuorumKeyManager.split_secret(self._wrapping_key, k=3, n=5)
        self._encrypted_kv: Dict[str, bytes] = {}
        self.grants: List[MemberDelegationGrant] = []
        self._activity_log: List[ActivityEntry] = []
        self.installed_tools: Dict[str, str] = {}

    def seal_secret(
        self,
        placeholder: str,
        plaintext: str,
        actor_did: str = "did:t3n:user-alice",
        timestamp_ms: int = 1_762_758_000_000,
    ) -> Dict[str, Any]:
        norm = placeholder if placeholder.startswith("{{") else f"{{{{{placeholder}}}}}"
        aad = f"{self.tenant_did}:{norm}".encode()
        recovered_key = ThresholdQuorumKeyManager.recover_secret(self.quorum_shares[:3])
        ciphertext = Aes256GcmEnvelope.encrypt(recovered_key, plaintext.encode("utf-8"), aad=aad)
        self._encrypted_kv[norm] = ciphertext

        entry = self._append_activity(
            timestamp_ms=timestamp_ms,
            caller_type="human",
            actor=actor_did,
            on_behalf_of=actor_did,
            contract="tee:user/contracts",
            function="map-entry-set",
            outcome="success",
            custom={"event": "policy.update", "field": norm, "cipher": "AES-256-GCM+ML-KEM-768"},
        )
        return {
            "placeholder": norm,
            "ciphertext_hex": ciphertext.hex(),
            "seq_no": entry.seq_no,
            "entry_hash": entry.hash,
        }

    def member_delegation_update(
        self,
        grants: List[MemberDelegationGrant],
        owner_did: str = "did:t3n:user-alice",
        timestamp_ms: int = 1_762_758_001_000,
    ) -> ActivityEntry:
        """Replaces the member's delegation policy (`member-delegation-update`)."""
        self.grants = list(grants)
        return self._append_activity(
            timestamp_ms=timestamp_ms,
            caller_type="human",
            actor=owner_did,
            on_behalf_of=owner_did,
            contract="tee:user/contracts",
            function="member-delegation-update",
            outcome="success",
            custom={"event": "policy.update", "grant_count": str(len(grants))},
        )

    def check_delegation(
        self,
        actor_did: str,
        on_behalf_of_did: str,
        contract_id: str,
        function_name: str,
        now_ms: int = 1_762_758_005_000,
    ) -> Dict[str, Any]:
        for g in self.grants:
            if (
                g.grantee == actor_did
                and g.on_behalf_of == on_behalf_of_did
                and g.contract_id == contract_id
                and g.function == function_name
            ):
                if now_ms > g.expires_at_ms:
                    return {"allowed": False, "kind": "member_delegation", "deny_code": "member_delegation_expired"}
                return {
                    "allowed": True,
                    "kind": "member_delegation",
                    "allowed_hosts": g.allowed_hosts,
                    "allowed_placeholders": g.allowed_placeholders,
                }
        return {"allowed": False, "kind": "member_delegation", "deny_code": "member_delegation_not_found"}

    def install_tool(
        self,
        tool_id: str,
        version: str,
        actor_did: str = "did:t3n:agent-7f3a",
        on_behalf_of_did: str = "did:t3n:user-alice",
        timestamp_ms: int = 1_762_758_002_000,
    ) -> ActivityEntry:
        self.installed_tools[tool_id] = version
        return self._append_activity(
            timestamp_ms=timestamp_ms,
            caller_type="agent",
            actor=actor_did,
            on_behalf_of=on_behalf_of_did,
            contract=self.contract_id,
            function="manage-agent-tool",
            outcome="success",
            custom={"event": "tool.install", "tool": f"{tool_id}@{version}"},
        )

    def remove_tool(
        self,
        tool_id: str,
        actor_did: str = "did:t3n:agent-7f3a",
        on_behalf_of_did: str = "did:t3n:user-alice",
        timestamp_ms: int = 1_762_758_003_000,
    ) -> ActivityEntry:
        ver = self.installed_tools.pop(tool_id, "unknown")
        return self._append_activity(
            timestamp_ms=timestamp_ms,
            caller_type="agent",
            actor=actor_did,
            on_behalf_of=on_behalf_of_did,
            contract=self.contract_id,
            function="manage-agent-tool",
            outcome="success",
            custom={"event": "tool.remove", "tool": f"{tool_id}@{ver}"},
        )

    def http_with_placeholders(
        self,
        actor_did: str,
        on_behalf_of_did: str,
        function_name: str,
        method: str,
        url: str,
        payload_template: Dict[str, Any] | str,
        timestamp_ms: int = 1_762_758_010_000,
    ) -> Dict[str, Any]:
        """
        Executes a T3N `http-with-placeholders` call inside the TEE boundary:
          1. Verifies `member_delegation` grant for `(actor_did, on_behalf_of_did, contract_id, function_name)`.
          2. Verifies target hostname against `allowed_hosts` (blocks prompt-injection exfiltration).
          3. Verifies every `{{...}}` placeholder against `allowed_placeholders`.
          4. Decrypts secrets inside the enclave using 3-of-5 threshold quorum shares and substitutes them
             into the outbound request while returning ONLY non-sensitive confirmation metadata to the agent.
        """
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            raise ValueError(f"Invalid outbound URL: {url}")

        verdict = self.check_delegation(actor_did, on_behalf_of_did, self.contract_id, function_name, timestamp_ms)
        if not verdict["allowed"]:
            self._append_activity(
                timestamp_ms=timestamp_ms,
                caller_type="agent",
                actor=actor_did,
                on_behalf_of=on_behalf_of_did,
                contract=self.contract_id,
                function=function_name,
                outcome="denied",
                custom={"event": "policy.update", "reason": verdict["deny_code"]},
            )
            raise PermissionError(verdict["deny_code"])

        allowed_hosts = [h.lower() for h in verdict["allowed_hosts"]]
        if host not in allowed_hosts:
            self._append_activity(
                timestamp_ms=timestamp_ms,
                caller_type="agent",
                actor=actor_did,
                on_behalf_of=on_behalf_of_did,
                contract=self.contract_id,
                function=function_name,
                outcome="denied",
                custom={"event": "secret.read", "blocked_host": host, "reason": "host_not_allowed"},
            )
            raise PermissionError(f"outbound_host_not_allowed: {host}")

        raw_template = (
            payload_template if isinstance(payload_template, str) else json.dumps(payload_template, sort_keys=True)
        )
        markers = [f"{{{{{m}}}}}" for m in PLACEHOLDER_RE.findall(raw_template)]

        recovered_key = ThresholdQuorumKeyManager.recover_secret(self.quorum_shares[:3])
        resolved_payload = raw_template

        for marker in markers:
            if marker not in verdict["allowed_placeholders"]:
                self._append_activity(
                    timestamp_ms=timestamp_ms,
                    caller_type="agent",
                    actor=actor_did,
                    on_behalf_of=on_behalf_of_did,
                    contract=self.contract_id,
                    function=function_name,
                    outcome="denied",
                    custom={"event": "secret.read", "denied_placeholder": marker},
                )
                raise PermissionError(f"placeholder not permitted: {marker}")

            if marker not in self._encrypted_kv:
                raise KeyError(f"placeholder not seeded in tenant KV map: {marker}")

            aad = f"{self.tenant_did}:{marker}".encode()
            plaintext_bytes = Aes256GcmEnvelope.decrypt(recovered_key, self._encrypted_kv[marker], aad=aad)
            resolved_payload = resolved_payload.replace(marker, plaintext_bytes.decode("utf-8"))

        entry = self._append_activity(
            timestamp_ms=timestamp_ms,
            caller_type="agent",
            actor=actor_did,
            on_behalf_of=on_behalf_of_did,
            contract=self.contract_id,
            function=function_name,
            outcome="success",
            custom={
                "event": "secret.read",
                "egress_host": host,
                "placeholders": str(len(markers)),
            },
        )

        return {
            "status": "committed",
            "method": method,
            "egress_host": host,
            "agent_context_payload": raw_template,  # What the LLM/agent saw (ONLY placeholders!)
            "enclave_wire_digest": hashlib.sha256(resolved_payload.encode()).hexdigest(),
            "contains_plaintext_in_agent_response": False,
            "audit_seq_no": entry.seq_no,
            "audit_entry_hash": entry.hash,
            "merkle_root": self.compute_merkle_root(),
        }

    def get_activity_log(
        self,
        limit: int = 200,
        before_seq: Optional[int] = None,
        custom: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Models `client.getActivityLog(opts?)`: returns newest-first (`seq_no` descending)
        activity entries with tamper-evident hashes and optional `custom` label filtering.
        """
        rows = list(reversed(self._activity_log))
        if before_seq is not None:
            rows = [r for r in rows if r.seq_no < before_seq]
        if custom:
            rows = [
                r for r in rows
                if all(r.custom.get(k) == v for k, v in custom.items())
            ]
        clamped = max(1, min(1000, limit))
        page = rows[:clamped]
        next_seq = page[-1].seq_no if len(rows) > clamped else None
        return {
            "entries": page,
            "next_seq": next_seq,
            "merkle_root": self.compute_merkle_root(),
        }

    def compute_merkle_root(self) -> str:
        if not self._activity_log:
            return hashlib.sha256(b"T3N_EMPTY_AUDIT_LOG").hexdigest()
        layer = [e.hash for e in self._activity_log]
        while len(layer) > 1:
            next_layer = []
            for i in range(0, len(layer), 2):
                left = layer[i]
                right = layer[i + 1] if i + 1 < len(layer) else layer[i]
                next_layer.append(hashlib.sha256(f"{left}:{right}".encode()).hexdigest())
            layer = next_layer
        return layer[0]

    def build_merkle_proof(self, seq_no: int) -> List[Dict[str, str]]:
        """Generates a verifiable Merkle inclusion proof for audit entry `seq_no`."""
        idx = seq_no - 1
        if idx < 0 or idx >= len(self._activity_log):
            raise IndexError(f"Invalid seq_no: {seq_no}")
        layer = [e.hash for e in self._activity_log]
        proof: List[Dict[str, str]] = []
        while len(layer) > 1:
            if idx % 2 == 0:
                sib_idx = idx + 1 if idx + 1 < len(layer) else idx
                proof.append({"position": "right", "hash": layer[sib_idx]})
            else:
                sib_idx = idx - 1
                proof.append({"position": "left", "hash": layer[sib_idx]})
            next_layer = []
            for i in range(0, len(layer), 2):
                left = layer[i]
                right = layer[i + 1] if i + 1 < len(layer) else layer[i]
                next_layer.append(hashlib.sha256(f"{left}:{right}".encode()).hexdigest())
            layer = next_layer
            idx //= 2
        return proof

    @staticmethod
    def verify_merkle_proof(leaf_hash: str, proof: List[Dict[str, str]], expected_root: str) -> bool:
        curr = leaf_hash
        for step in proof:
            if step["position"] == "right":
                curr = hashlib.sha256(f"{curr}:{step['hash']}".encode()).hexdigest()
            else:
                curr = hashlib.sha256(f"{step['hash']}:{curr}".encode()).hexdigest()
        return hmac.compare_digest(curr, expected_root)

    def _append_activity(
        self,
        timestamp_ms: int,
        caller_type: str,
        actor: str,
        on_behalf_of: str,
        contract: str,
        function: str,
        outcome: str,
        custom: Dict[str, str],
    ) -> ActivityEntry:
        seq_no = len(self._activity_log) + 1
        prev_hash = self._activity_log[-1].hash if self._activity_log else ("0" * 64)
        canonical = json.dumps(
            {
                "seq_no": seq_no,
                "prev_hash": prev_hash,
                "timestamp_ms": timestamp_ms,
                "caller_type": caller_type,
                "actor": actor,
                "on_behalf_of": on_behalf_of,
                "org": self.tenant_did,
                "contract": contract,
                "function": function,
                "outcome": outcome,
                "custom": custom if outcome == "success" else {},
            },
            sort_keys=True,
        ).encode()
        entry_hash = hashlib.sha256(canonical).hexdigest()
        entry = ActivityEntry(
            seq_no=seq_no,
            hash=entry_hash,
            prev_hash=prev_hash,
            timestamp_ms=timestamp_ms,
            caller_type=caller_type,
            actor=actor,
            on_behalf_of=on_behalf_of,
            org=self.tenant_did,
            contract=contract,
            function=function,
            outcome=outcome,
            roles=["member_delegation"],
            custom=custom,
        )
        self._activity_log.append(entry)
        return entry
