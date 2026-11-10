"""
T3-VaultGuard Model Context Protocol (MCP) Server & Agent Reasoning Firewall.
Ensures LLM agents plan and invoke tools exclusively via sealed T3N placeholders
(`{{user.passport_no}}`, `{{user.card_no}}`, `{{user.email}}`, `{{org.iban}}`).
"""

from __future__ import annotations

from typing import Any, Dict, List

from .enclave import (
    MemberDelegationGrant,
    SmartVerifiableCredential,
    T3nVaultGuardEnclave,
)


class VaultGuardMcpServer:
    """
    MCP Tool Server wrapping a T3N Confidential Enclave (`z:t3n-org-99a1:vaultguard`).
    """

    def __init__(self, enclave: T3nVaultGuardEnclave | None = None):
        self.enclave = enclave or self._create_default_enterprise_enclave()

    @staticmethod
    def _create_default_enterprise_enclave() -> T3nVaultGuardEnclave:
        enc = T3nVaultGuardEnclave(tenant_did="did:t3n:org-99a1")
        enc.seal_secret("{{profile.first_name}}", "Alice", "did:t3n:user-alice", 1_762_758_000_100)
        enc.seal_secret("{{profile.last_name}}", "Vance", "did:t3n:user-alice", 1_762_758_000_200)
        enc.seal_secret("{{user.passport_no}}", "N84920174", "did:t3n:user-alice", 1_762_758_000_300)
        enc.seal_secret("{{user.email}}", "alice.vance@acme-corp.io", "did:t3n:user-alice", 1_762_758_000_400)
        enc.seal_secret("{{user.card_no}}", "4532-9910-8821-4091", "did:t3n:user-alice", 1_762_758_000_500)
        enc.seal_secret("{{user.tax_id}}", "SG-UEN-202699182K", "did:t3n:user-alice", 1_762_758_000_600)
        enc.seal_secret("{{org.iban}}", "GB33BUKB20201555555555", "did:t3n:user-alice", 1_762_758_000_700)

        enc.member_delegation_update(
            [
                MemberDelegationGrant(
                    grantee="did:t3n:agent-7f3a",
                    on_behalf_of="did:t3n:user-alice",
                    contract_id="z:t3n-org-99a1:vaultguard",
                    version_req="^0.4.2",
                    function="book-offer",
                    scopes=[{"path": "book-offer", "access": ["read"]}],
                    allowed_hosts=["api.duffel.com"],
                    allowed_placeholders=[
                        "{{profile.first_name}}",
                        "{{profile.last_name}}",
                        "{{user.passport_no}}",
                        "{{user.email}}",
                    ],
                ),
                MemberDelegationGrant(
                    grantee="did:t3n:agent-7f3a",
                    on_behalf_of="did:t3n:user-alice",
                    contract_id="z:t3n-org-99a1:vaultguard",
                    version_req="^0.4.2",
                    function="settle-treasury-invoice",
                    scopes=[{"path": "settle-treasury-invoice", "access": ["read"]}],
                    allowed_hosts=["api.stripe.com"],
                    allowed_placeholders=[
                        "{{user.card_no}}",
                        "{{org.iban}}",
                        "{{user.tax_id}}",
                    ],
                ),
            ]
        )
        enc.install_tool("duffel-flight-booker", "2.4.0")
        enc.install_tool("stripe-treasury-settler", "1.9.1")
        return enc

    def list_mcp_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "t3n_book_flight_with_placeholders",
                "description": "Book an executive flight via T3N TEE Enclave using sealed placeholders ({{user.passport_no}}, {{user.email}}).",
                "allowed_hosts": ["api.duffel.com"],
            },
            {
                "name": "t3n_settle_invoice_with_placeholders",
                "description": "Settle a corporate invoice via T3N TEE Enclave using sealed placeholders ({{user.card_no}}, {{org.iban}}, {{user.tax_id}}).",
                "allowed_hosts": ["api.stripe.com"],
            },
            {
                "name": "t3n_verify_reusable_kyc_vc",
                "description": "Verify a Terminal 3 Smart VC zero-knowledge compliance presentation without exposing raw documents.",
                "allowed_hosts": ["compliance.terminal3.io"],
            },
        ]

    def invoke_flight_booking(self, offer_id: str, target_url: str = "https://api.duffel.com/air/orders") -> Dict[str, Any]:
        payload_template = {
            "data": {
                "type": "instant",
                "selected_offers": [offer_id],
                "passengers": [
                    {
                        "given_name": "{{profile.first_name}}",
                        "family_name": "{{profile.last_name}}",
                        "identity_document_number": "{{user.passport_no}}",
                        "email": "{{user.email}}",
                    }
                ],
            }
        }
        return self.enclave.http_with_placeholders(
            actor_did="did:t3n:agent-7f3a",
            on_behalf_of_did="did:t3n:user-alice",
            function_name="book-offer",
            method="POST",
            url=target_url,
            payload_template=payload_template,
        )

    def invoke_treasury_settlement(self, invoice_id: str, amount_usd: int, target_url: str = "https://api.stripe.com/v1/payment_intents") -> Dict[str, Any]:
        payload_template = {
            "invoice_id": invoice_id,
            "amount_cents": amount_usd * 100,
            "currency": "usd",
            "payment_method_card": "{{user.card_no}}",
            "settlement_iban": "{{org.iban}}",
            "entity_tax_id": "{{user.tax_id}}",
        }
        return self.enclave.http_with_placeholders(
            actor_did="did:t3n:agent-7f3a",
            on_behalf_of_did="did:t3n:user-alice",
            function_name="settle-treasury-invoice",
            method="POST",
            url=target_url,
            payload_template=payload_template,
        )
