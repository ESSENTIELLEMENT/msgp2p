# Changelog

## 0.1.0

- `FileKeyVault`: the device identity in a JSON file with mode 0600, written atomically (temporary file,
  then rename), one identity under concurrent first calls (a lock per path in the process, an exclusive
  `<path>.lock` across processes), `KeyVaultCorruptedError` for unreadable contents (proposal 0001, step 2;
  Discussion #10).
- The temporary file is created exclusively (`O_EXCL`) in a private `mkdtemp` directory and restricted to
  0600 before the seeds are written; a directory writable by group or others, or a symlink in place of the
  vault or its lock file, is refused (code scanning review on the pull request).
