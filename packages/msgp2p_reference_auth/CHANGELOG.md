# Changelog

## 0.1.0

- Initial release of `ReferenceMembershipSource` implementing `MembershipSource` from `msgp2p_core` over
  `HttpExecutor` against the reference server's `/auth/register`, `/auth/login`, and `/sync/revocations`
  endpoints (proposal 0001, step 4; §3, §4, §7, §9.1–9.2).
- Cryptographic verification of `MembershipCert` and active `RevocationNotice`s against `pinnedServerKey`,
  constant-time group and device public-key binding checks, `KeyRole` (`member` / `tracker`) parsing, and
  optional `GatewayClient` bearer-token synchronization.
