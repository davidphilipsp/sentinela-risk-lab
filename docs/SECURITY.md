# Security model: encryption and zero traces

**Base rule of the system:** every file that enters Sentinela is cleaned, encrypted and leaves no readable
trace. Data is only ever readable in RAM, during a run. This is not an option you switch on. The study
loader **refuses plaintext inputs**.

## 1. Data life cycle

```
 ~/Downloads/export.csv
        │  sentinela ingest export.csv --dataset activity
        ▼
 [RAM] read ─► drop personal data (header + content) ─► normalize to clean UTF-8
        │      (no BOM, no original name, no file metadata)
        ▼
 vault/<random>.sntl   AES-256-GCM, verified by decrypting, timestamp neutralized (2000-01-01)
        │      original: overwritten + deleted · its "recent files" entry and thumbnail removed
        ▼
 sentinela run study.yaml
        │  [RAM] decrypt ─► analyze (DuckDB in memory, spills into RAM) ─► report
        ▼
 vault/runs/run-<random>.sntl   one encrypted bundle (HTML, PDF, evidence, tables), no timestamps
        │
        ├─ sentinela view <run>      → decrypted into RAM (/dev/shm) for reading
        └─ sentinela export <run>    → explicit plaintext copy for sharing (PDF metadata stripped)
```

On disk you will only ever find: `.sentinela/keyring.json` (encrypted key material), `vault/*.sntl`
(encrypted), study/config YAML files (no data), and the program itself.

## 2. Cryptography

| Item | Choice |
|---|---|
| Cipher | AES-256-GCM (authenticated), `cryptography` library (OpenSSL) |
| Key hierarchy | passphrase → **scrypt** (N=2¹⁵, r=8, p=1, 16-byte salt) → key-encryption key → unwraps a random 256-bit **data key** + the pseudonymization secret |
| Per-file key | HMAC-SHA256(data key, random 128-bit file id) → every file has its own key; no nonce reuse across files |
| File format | header (magic, version, kind, file id) + 4 MiB chunks; nonce = chunk index + **final flag**; header authenticated in every chunk |
| Detects | any modified byte, chunk reordering, **truncation**, wrong key, foreign files |
| Manifest | the vault index (labels, columns, hashes) is itself encrypted |
| Passphrase | ≥ 12 characters; `sentinela passwd` changes it without re-encrypting data |

**There is no recovery.** If the passphrase is lost, the vault cannot be opened. Keep it in a password manager or
a sealed envelope. Back up `.sentinela/keyring.json` together with `vault/`: both are useless without the
passphrase.

## 3. What "clean" means at ingestion

| Trace | Treatment |
|---|---|
| Direct personal data (name, e-mail, phone, CPF, address, birth date, IP, card/PIX) | columns dropped **before encryption**, detected by header **and by content** (≥ 30% of values look like e-mail/CPF/phone/card). The contract's player ID column is kept and pseudonymized at analysis |
| Original file name (often reveals the client or campaign) | never stored; only its SHA-256 |
| File metadata (owner, timestamps, xattrs, encoding, BOM) | content is rewritten from scratch as clean UTF-8; vault files get a fixed timestamp |
| The original file | overwritten with random data, fsync, truncated, renamed and deleted (asks first; `--keep-source` to skip) |
| Desktop traces of the original | its entry in `~/.local/share/recently-used.xbel` and its thumbnail in `~/.cache/thumbnails` are removed |
| Logs | Sentinela writes **no log files**. Terminal output shows aggregates, labels and pseudonyms only |

> On SSDs and journaling file systems, no software overwrite is guaranteed to reach the original blocks.
> **Full-disk encryption (LUKS) is what makes such leftovers unreadable.** That is why `doctor` treats it as
> mandatory.

## 4. Process hardening (every command)

- `umask 077`: everything created is private to the user.
- Core dumps disabled (`RLIMIT_CORE = 0`), and the process is marked non-dumpable (`prctl PR_SET_DUMPABLE 0`), so a crash cannot write memory with data to disk.
- `TMPDIR` and DuckDB's spill directory point to the RAM workspace.
- The RAM workspace (`/dev/shm/sentinela-*`, mode 700) is wiped at the end of every command, on errors, on exit and on SIGTERM/SIGHUP.
- DuckDB cannot download extensions; there is no network code anywhere in the package.

## 5. Commands

| Command | Purpose |
|---|---|
| `sentinela init` | create the keyring (passphrase asked twice) |
| `sentinela ingest FILE --dataset X [--label L] [--map "Header:col"] [--only-contract] [--keep-source] [--yes]` | the **only** way in |
| `sentinela vault` · `vault rm LABEL` | list / securely remove datasets |
| `sentinela runs` · `runs rm ID` | list / securely remove reports |
| `sentinela view [ID] [--open]` | read a report (decrypted into RAM) |
| `sentinela export ID --to DIR [--only html,pdf,tables,json]` | explicit plaintext copy for sharing |
| `sentinela export-segment STUDY SEG [--reveal]` | campaign list; written to RAM unless `--out` |
| `sentinela clean [--traces] [--apply]` | wipe RAM workspaces; list/delete plaintext files; clean shell history and recent-files entries |
| `sentinela doctor` | check the machine (below) |
| `sentinela passwd` | change the passphrase |

## 6. `sentinela doctor` checks

| Check | Expected |
|---|---|
| Project disk on LUKS (dm-crypt) | **required** |
| Swap | none, or on an encrypted device (otherwise RAM pages with data may reach the disk) |
| RAM workspace | `/dev/shm` is tmpfs |
| Network | no interface up during analysis |
| Crash reporter (apport) | disabled |
| Keyring / vault permissions | 600 / 700 |
| Plaintext CSV/XLSX in the project | none |
| CSV/XLSX in `~/Downloads` | none (ingest or shred them) |
| Shell history / recent files | no mentions of Sentinela or project files |

## 7. Machine setup checklist (Ubuntu)

- [ ] Install Ubuntu with **"Encrypt the new Ubuntu installation" (LUKS)**. This also encrypts the default swap file.
- [ ] Separate user account; screen lock ≤ 5 min.
- [ ] `sudo systemctl disable --now apport`
- [ ] Network off during analysis, or `sudo ufw default deny outgoing && sudo ufw enable`.
- [ ] No cloud sync clients or AI assistants with file access on this machine.
- [ ] Shell: Ubuntu's default `HISTCONTROL=ignoreboth` lets you **start a command with a space** so it is not recorded, e.g. ` sentinela ingest ~/Downloads/x.csv --dataset activity`. After a session: `sentinela clean --traces --apply`, then `history -c`.
- [ ] Open reports in a **private browser window** (`sentinela view --open`): browsers keep caches and history.
- [ ] Transfer the installation zip on a dedicated USB stick and verify `sha256sum -c SHA256SUMS.txt`.
- [ ] Run `sentinela doctor` until there are no FALHA results.

## 8. Test mode (never in production)

The test suite sets `security.plaintext_inputs/plaintext_outputs: true` and a passphrase through
`SENTINELA_PASSPHRASE`. Evidence and reports produced that way are labelled "plaintext (modo de teste)" in their
metadata. Do not use either setting with real data.
