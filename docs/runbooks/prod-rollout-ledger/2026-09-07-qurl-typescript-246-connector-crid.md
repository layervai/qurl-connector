# 2026-09-07 · qurl-typescript #246 · Connector CRID cutover

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/qurl-typescript/pull/246

Connector uses CRID for configuration, continuity, and management. Public keys remain verification data.

- [ ] Pre-rollout: deploy the matching service producer and NHP native receiver through the normal candidate deployment path; check cold create and warm CRID continuity with the new Go client.
- [ ] Rollout: update operator route pins to `crid` and automation to `remove --crid`. This release rejects version-2 identity caches. Complete or resolve pending old operations before retiring old state; never delete an unresolved retry record to bypass the gate.
- [ ] Post-rollout: check native discovery, tunnel admission, local service access, restart, link mint/revoke, and route removal with the released Connector.
- [ ] Rollback: restore the matched service/NHP/client release set and its saved identity state together. Do not reinterpret version-3 state with an old client.

- [ ] Cutover: drain in-flight discovery before the matched deployment. Old replay envelopes and cache version 2 are rejected. Reconcile every unresolved nonce before creating fresh state; preserve the original records for rollback. Do not automatically re-nonce an unknown mutation.
