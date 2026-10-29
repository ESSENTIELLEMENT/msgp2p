# msgp2p_keyvault_file

A file-based `KeyVault` for headless msgp2p nodes: Linux CLI runners, Raspberry Pi gateways, on-board
computers. It keeps the node's identity (its Ed25519 and X25519 seeds) across restarts, as `FR-ID-01` requires.
Phones use the keystore vault of `msgp2p_flutter` instead.

```dart
import 'package:msgp2p_keyvault_file/msgp2p_keyvault_file.dart';

final vault = FileKeyVault('/var/lib/my-node/identity.json');
final (:seeds, :created) = await vault.loadOrCreate();
```

- The file has mode **0600** and is written atomically. Put it in a directory only the node's user can read.
- **Keep it on the device.** A copy on a second device is the same identity there, and two devices with one
  identity author conflicting messages. Exclude it from backups that restore to other machines.
- Unreadable contents throw `KeyVaultCorruptedError`. The vault never replaces them with a new identity by
  itself: the host decides, with `erase()`.
- Keep the identity and the message store together. If the store is lost while the identity is kept, the node
  refuses to author (`UnsynchronizedIdentityException`) until the store is restored or the identity erased.
- Windows has no POSIX modes; there the file gets the directory's default permissions.

Design: [proposal 0001](../../proposals/0001-host-integration-ports.md), step 2;
[Discussion #10](https://github.com/ESSENTIELLEMENT/msgp2p/discussions/10).
