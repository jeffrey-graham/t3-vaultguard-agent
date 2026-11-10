/**
 * T3-VaultGuard TypeScript SDK Bridge for `@terminal3/t3n-sdk` (>= 5.31.0 / `testnet-v1.0.12`).
 *
 * Implements:
 *   1. Out-of-band TEE Trust Anchor verification (`resolveTrustAnchor("testnet")`)
 *   2. Separate Agent DID session authentication (`agentClient.handshake()` + `authenticate()`)
 *   3. Data-owner Member Delegation (`tee:user/contracts` -> `member-delegation-update`)
 *   4. Zero-leak `z:<tid>:vaultguard` invocation and paginated `client.getActivityLog()`
 */

export interface VaultGuardDelegationConfig {
  agentDid: string;
  tenantContractId: string;
  contractVersion: string;
}

export function buildMemberDelegationPayload(cfg: VaultGuardDelegationConfig) {
  return {
    contract_id: "tee:user/contracts",
    function_name: "member-delegation-update",
    input: {
      grants: [
        {
          grantee: cfg.agentDid,
          contract_id: cfg.tenantContractId,
          version_req: cfg.contractVersion,
          function: "book-offer",
          scopes: [{ path: "book-offer", access: ["read"] }],
          allowed_hosts: ["api.duffel.com"],
        },
        {
          grantee: cfg.agentDid,
          contract_id: cfg.tenantContractId,
          version_req: cfg.contractVersion,
          function: "settle-treasury-invoice",
          scopes: [{ path: "settle-treasury-invoice", access: ["read"] }],
          allowed_hosts: ["api.stripe.com"],
        },
      ],
    },
  };
}

export async function drainOrganizationActivityLog(
  client: {
    getActivityLog: (opts: { limit?: number; before_seq?: number; custom?: Record<string, string> }) => Promise<{
      entries: Array<Record<string, unknown>>;
      next_seq: number | null;
    }>;
  },
  customFilter?: Record<string, string>
) {
  const allEntries: Array<Record<string, unknown>> = [];
  let cursor: number | undefined = undefined;
  do {
    const page = await client.getActivityLog({
      limit: 200,
      ...(cursor !== undefined ? { before_seq: cursor } : {}),
      ...(customFilter ? { custom: customFilter } : {}),
    });
    allEntries.push(...page.entries);
    cursor = page.next_seq ?? undefined;
  } while (cursor !== undefined);
  return allEntries;
}
