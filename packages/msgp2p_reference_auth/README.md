# msgp2p_reference_auth

`MembershipSource` adapter for the `msgp2p` reference server (`/auth/register`, `/auth/login`, and
`/sync/revocations`), built over `HttpExecutor` from `msgp2p_core` (Proposal 0001, Step 4).

Host applications that already have their own user sign-in and group-membership backend should implement
`MembershipSource` directly against their own API instead of depending on this package.

```dart
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:msgp2p_reference_auth/msgp2p_reference_auth.dart';

final gateway = GatewayClient(baseUrl: 'http://127.0.0.1:8000/api/v1');
final membership = ReferenceMembershipSource(
  baseUrl: 'http://127.0.0.1:8000/api/v1',
  username: 'alice',
  password: 'strong-password-123',
  pinnedServerKey: serverPubkey,
  gatewayClient: gateway, // keeps gateway.authToken updated on refresh
);

final grant = await membership.fetch(groupId, memberPublicKeys);
```

## Security & Hybrid Revocation Guarantees (§9.1)

- Authenticates against `/auth/login` (automatically registering on first use via `/auth/register` when
  `autoRegister: true`, while preserving `401` errors on wrong passwords for existing accounts).
- Populates `MembershipGrant.revocations` from inline login revocations or `GET /sync/revocations`, so the
  node receives active server-signed `RevocationNotice`s atomically alongside rotated group key epochs.
- Cryptographically verifies the certificate and every `RevocationNotice` against `pinnedServerKey` (as well
  as `GroupId` and `MemberPublicKeys` bindings) before updating `gatewayClient.authToken` or returning the
  `MembershipGrant`.

Design: [Proposal 0001](../../proposals/0001-host-integration-ports.md), Step 4 (§3, §4, §7, §9.1–9.2).
