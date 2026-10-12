# Launcher isolation and restoration

The launcher requires verified Windows Firewall isolation before installing or starting a modified client. Isolation remains until recorded files and shared system changes are restored and independently verified. This verification covers sc-offline's transaction; it does not establish official-service compatibility or a ban guarantee.

## Commands

`sc-offline.exe [play|install|uninstall|status|update|help] [--game <folder>] [--dry-run] [--skip-eac-check]`

- `play`: establish/verify isolation, journal originals, install the mod, supervise the managed game, and restore when it exits. If restoration fails, retain recovery information and isolation.
- `install`: the same preparation, with persistent rules and installation. Use controlled `play` afterward. Rules survive launcher exit; do not launch the modified installation through the official launcher or another shortcut.
- `uninstall`: restore the recorded transaction, verify original presence/hashes and absence of unresolved loadable mod files, then remove only its owned rules. Close the game, RSI Launcher, CrashHandler, and relevant EAC processes first.
- `status`: read actual journal/file/rule state. Returns nonzero for unknown or recovery-required state. Displays other known dirty installations.
- `update`: existing verified GitHub asset/manifest update workflow; does not restore a modified game installation.
- `--dry-run`: describe actions without installing the mod or changing system isolation.
- `--skip-eac-check`: skips the file-presence EAC preflight only. It cannot override mandatory isolation, running-component checks, or journal validation.

The elevated helper owns the transaction; the game starts with the existing normal-rights launch path. Setup requires the selected game's executable and resolved RSI Launcher/CrashHandler paths. Unresolved components stop setup. Only one shared-state transaction may be dirty at a time.

## Network configuration

`block_network = on` is mandatory. `off` and malformed network settings stop play/install before modification. `multiplayer = off` is the compiled and shipped default.

Opt-in multiplayer uses explicit peers and UDP ports:

```ini
multiplayer = on
multiplayer_peers = 192.168.1.20,192.168.1.21
multiplayer_ports = 64090
```

Up to eight IPv4 peers and eight ports (1024–65535) are allowed. CIDRs, broad LAN exceptions, multicast/broadcast/loopback peers, and old nonempty `multiplayer_allow` settings are rejected. Align allowed ports with the multiplayer plugin's host/join settings; an out-of-policy port remains blocked. Selected peers are passed to the plugin as /32 scope entries.

The firewall blocks IPv6 and all non-UDP protocols for the game. UDP exceptions apply only to selected peer/port tuples; companion executables stay fully blocked. The implementation partitions blocking rules because an explicit Windows Firewall block overrides a conflicting allow. An unsupported policy stops setup rather than widening access. Isolation relies on Windows Firewall filtering; local loopback and traffic relayed by unrelated local applications are outside a promise of complete machine isolation.

Each policy is tied to an installation identity and transaction. Verification checks paths, directions, actions, enabled state, profiles, protocol, addresses, ports, interfaces, firewall services, and local-policy availability. The launcher rechecks immediately before launch and during supervised play. Loss of verification stops the managed game and retains recovery state. Monitoring has a finite polling interval; persistent direct launches and administrator changes cannot receive a zero-exposure guarantee.

Changing the policy or package of a persistent installation requires Uninstall first. Resume validates the installed hashes and the requested policy rather than accepting an old rule name.

## Durable recovery

Records live under the known Windows ProgramData folder:

`sc-offline/verified-v1/<installation-key>/journal`

The store is writable only by Administrators/System and readable for status. Journals use bounded, versioned, checksummed records; writes are staged, flushed, and atomically replaced. Original file hashes, verified backups, replacement hashes, rule ownership, and action intents/completions support recovery after interruption. Installation aliases are canonicalized; changed directory identities and reparse arrangements are rejected.

A missing, damaged, unreadable, or contradictory journal is unknown/recovery-required, not evidence that nothing changed. Do not manually delete recovery records or firewall rules to clear a banner. Review the specific error, resolve the conflict, and rerun Uninstall. Locked files, changed originals, failed XML restoration, missing backups, unresolved companion processes, or conflicting shared EAC state prevent network release.

EAC changes preserve the exact executable in the protected recovery store instead of overwriting an `.exe.bak`. The executable is removed while the recorded transaction is modified and restored from verified original bytes. Existing `.bak` files are conflicts. Hosts edits are journaled; concurrent edits conflict instead of being silently overwritten. An EAC download-host mapping is separate from network isolation, and executable absence does not prove all anti-cheat components are inactive.

## Legacy installations

Old `pc-changes.txt`, `sc-offline.installed`, and `.sc-offline-backup` evidence is not adopted as a clean baseline. A new installation attempt first establishes blocking for its explicitly selected path, then quarantines legacy ambiguity without deleting old rules/records. An unrecorded installed sc-offline DLL is similarly refused. Legacy shared ownership cannot be inferred from a rule name; manually reconcile the old transaction with its originals while keeping blocking, rather than using the new restore command to guess.

The new Uninstall only restores its valid transaction. Unresolved legacy evidence prevents successful verification. Existing third-party `dinput8.dll` files are preserved/restored, but they keep isolation and recovery-required status because a loadable modification remains.

## Status labels

- **Offline isolation verified**: modified transaction with currently matching observed rules. It does not authorize official play.
- **Restoration verified**: recorded originals match, unresolved mod/legacy conditions are absent, required processes are closed, and owned rules are absent.
- **Recovery required**: a known unfinished or conflicting transaction.
- **State unknown**: no valid evidence sufficient for the claim, including a never-managed installation.

These labels replace “Safe to go online.” The launcher does not scan or certify the complete official game installation.

## Wine and Linux

Play/install are disabled until a supported host isolation adapter can enforce the same contract. The Linux script also refuses restoration requiring native Windows policy verification. Status/help/update remain available where Wine supports them. A hosts entry alone is insufficient.

## Logs, updates, and plugins

Session logs remain available for diagnosis. The existing optional crash-report bundle and log-cleanup prompts are separate from restoration; deleting logs is not a safety control. GitHub update digest/manifest verification, plugin selection, and game feature behavior remain on their existing paths. See [features](features.md), [plugin UI](plugin-ui.md), and [build instructions](build.md).

## Validation

Standalone native tests: configure `tests/launcher_safety` with MSVC x64, build, then run CTest. They exercise transaction failures, native temporary-file recovery, corrupted journals, persistent policy changes, and compiled peer/port predicates without modifying a real game installation.

`windows_integration_tests --exercise-rules <evidence-file>` and `--exercise-multiplayer <evidence-file>` require elevation and operate only on the test executable's own rules. `--cleanup <evidence-file>` retries its journaled cleanup. These adapter checks prove rule representation, verification, disabled-rule rejection, and owned-rule removal. They do not by themselves prove off-host traffic blocking. Separate controlled-peer TCP/UDP IPv4/IPv6 and reboot tests remain required before treating the build as runtime accepted. Never use official services as test endpoints.
