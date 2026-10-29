# msgp2p_keyvault_file

A file-based `KeyVault` for headless msgp2p nodes: Linux CLI runners, Raspberry Pi gateways, on-board
computers. It keeps the node's identity (its Ed25519 and X25519 seeds) across restarts, as `FR-ID-01` requires.
Phones use the keystore vault of `msgp2p_flutter` instead.

```dart
import 'package:msgp2p_keyvault_file/msgp2p_keyvault_file.dart';

final vault = FileKeyVault('/var/lib/my-node/identity.json');
final (:seeds, :created) = await vault.loadOrCreate();
```

- The file has mode **0600** and is written atomically: created exclusively in a private temporary directory
  (mode 0700, unpredictable name), restricted before the seeds are written, then renamed into place.
- Put it in a directory that belongs to the node's user and that only that user can write to. The vault
  refuses (`FileSystemException`) a directory that group or others can write to (such as `/tmp`), and a
  symbolic link in place of the vault or its `.lock` file. Dart cannot read a file's owner, so it cannot check
  who owns the directory: that part is the host's job.
- **Keep it on the device.** A copy on a second device is the same identity there, and two devices with one
  identity author conflicting messages. Exclude it from backups that restore to other machines.
- Unreadable contents throw `KeyVaultCorruptedError`. The vault never replaces them with a new identity by
  itself: the host decides, with `erase()`.
- Keep the identity and the message store together. If the store is lost while the identity is kept, the node
  refuses to author (`UnsynchronizedIdentityException`) until the store is restored or the identity erased.
- Windows has no POSIX modes; there the file gets the directory's default permissions.

Design: [proposal 0001](../../proposals/0001-host-integration-ports.md), step 2;
[Discussion #10](https://github.com/ESSENTIELLEMENT/msgp2p/discussions/10).
