# Offline isolation and verified restoration

Date: 2026-10-11
Repository: https://github.com/UncommonDLL/sc-offline
Baseline: 1ac5308a65ac0ba7955e4108bd1dc800449cfa69
Status: Design approved in chat; written specification awaiting review.

## Purpose and scope

Reduce accidental exposure of a modified Star Citizen installation to official services. Implement the five approved changes: conditional firewall removal, isolated persistent installation, exact firewall verification, mandatory isolation with narrow opt-in multiplayer, and durable installation-specific recovery with truthful status.

Success means the launcher never deliberately removes its network protection while a recorded modification remains unresolved, never installs or starts a modified client without verified isolation, and never reports successful restoration from configuration intent or absence of a marker alone. No anti-cheat evasion, concealment, log erasure, or assertion of ban safety is included.

Modify the existing launcher lifecycle and supporting configuration, Linux wrapper, documentation, build integration, and tests. Preserve unrelated game hooks and plugin behavior. Local build and testing are authorized; publication and interaction with official services are outside this implementation.

## Architecture

Introduce focused launcher components for transaction state, durable storage, firewall policy, and restoration verification. Keep CLI and GUI on a shared lifecycle. Separate policy decisions from Windows adapters so failures can be tested without changing a real game installation or firewall.

Resolve the installation's final canonical path and stable directory identity before changing anything. Reject ambiguous aliases, inaccessible paths, or unsupported reparse-point arrangements. Key journals and rule ownership to that identity. Record canonical channel, Bin64, game executable, and discovered companion executable paths. A changed directory identity requires recovery rather than silently adopting an old journal.

Use a machine-wide exclusive transaction lock for operations touching shared EAC/hosts state, and persistent ownership records linking those shared changes to their transaction. A second install/play transaction must not take over shared changes owned by a dirty installation. Read-only status remains available. CLI helpers independently validate installation identity and transaction ownership.

## State and durable records

States are PREPARING, ISOLATED, MODIFIED, RESTORING, FILES_RESTORED, RELEASE_PENDING, and RESTORED. An incomplete, unreadable, incompatible, or contradictory transaction becomes RECOVERY_REQUIRED or UNKNOWN. A missing journal does not erase evidence of previous modifications.

Each versioned journal contains installation identity, transaction ID, mode, state, exact owned firewall specifications, original file presence and SHA-256, backup locations and hashes, intended replacement hashes, EAC/hosts ownership, and per-action intent/completion records. Store recovery records under a restricted ProgramData directory. Record all paths and states in a validated structured format with bounded input sizes.

Before any mutation, atomically write and flush its intent. After mutation, verify its postcondition and durably record completion. Write a temporary journal on the same volume, flush it, then atomically replace the journal with write-through semantics. Journal errors stop progress. Never truncate the only valid recovery record. Backups are verified and durable before replacing originals. Preserve prior EAC backups; conflicting states require recovery and must not overwrite evidence.

Retain a completed restoration receipt. On restart, infer pending actions from actual file/rule properties and the journal rather than assuming the last command completed. Missing backups, hash conflicts, and unexplained changes require user-visible recovery; do not delete unknown files to make the state appear clean.

## Isolation policy and verification

All install/play operations require isolation. Reject block_network=off with an actionable error. Default multiplayer to off in both compiled defaults and the shipped INI. Existing configurations explicitly enabling multiplayer must satisfy the new peer/port validation; old broad multiplayer_allow ranges are rejected with migration instructions.

Use structured Windows Firewall APIs rather than parsing localized command output or accepting a rule name. Each owned rule has a transaction/installation-specific identity. Verify application path, direction, enabled state, block/allow action, profile coverage, protocol, ports, remote addresses, and ownership. Verify the firewall service and required profiles are enabled and that local policy is permitted to apply. Unsupported or unverifiable policy states fail closed before file mutation.

Default mode blocks inbound and outbound IPv4/IPv6 traffic for the selected game and resolved companion executables. Discover companion executable paths and relevant running processes; an unresolved potentially active companion blocks setup. Do not claim that this proves coverage of every possible external uploader.

Multiplayer is explicit opt-in. Accept bounded explicit IPv4 peer addresses and a bounded UDP port selection only; do not accept CIDR ranges or broad private-network exceptions. Enforce peer/port restrictions on outbound and inbound policy. Windows explicit block precedence means a blanket block plus an allow rule is insufficient: partition the blocked address/protocol/port space so only approved UDP peer/port tuples are excluded. If this policy cannot be represented and verified, refuse multiplayer and offer the fully blocked mode. Never silently broaden exceptions. IPv6 stays fully blocked.

Verify policy after creation, before DLL/XML mutation, immediately before launch, and during the supervised game session. On detected isolation loss, stop the supervised game and retain dirty recovery state; errors in monitoring must be visible and handled conservatively. Monitoring cannot guarantee zero exposure against an administrator or policy change between checks. Persistent install rules survive reboot; direct launches outside the launcher cannot receive its prelaunch verification or monitoring, and documentation/status must disclose that limit.

Windows and Wine use the same safety contract. Wine install/play is refused until a supported host isolation adapter exists. Status/help and a supported restoration-only path remain available; the Linux wrapper must not present an EAC hosts entry as network isolation.

## Installation and play

Persist PREPARING and intended rules before installing protection. Verify isolation, persist ISOLATED, back up and verify original files, then apply DLL/XML changes with write-ahead records. Persist MODIFIED only after installed hashes match. Any failure invokes the shared restoration procedure and preserves protection until verification succeeds.

Persistent install follows the same sequence and leaves rules plus journal in place when the command exits. It must not advise starting through the official launcher. Subsequent controlled play revalidates the existing transaction and policy, rather than treating installed files as a fresh baseline. Do not automatically choose a different installation to resolve a dirty transaction.

EAC preflight is separate from the isolation gate. Check relevant running components before mutation, validate exact hosts tokens and mappings, and record original shared state. --skip-eac-check cannot bypass mandatory isolation or transaction checks. Every EAC restoration conflict contributes to failed restoration.

## Restoration and network release

Normal game exit, startup failure, failed install, explicit uninstall, and crash recovery use the same procedure:

1. Acquire ownership locks and validate journal plus installation identity.
2. Establish or reverify isolation before handling a dirty transaction.
3. Ensure relevant game/companion processes are absent; uncertain process inspection fails closed.
4. Persist RESTORING and restore all recorded files and shared EAC/hosts changes, checking every operation and original hash/presence.
5. Verify there are no unresolved recorded mutations, backup conflicts, loadable unverified dinput8.dll files, or active relevant processes. Persist FILES_RESTORED.
6. Recheck restoration immediately before network release; persist RELEASE_PENDING and remove only this transaction's owned rules, with write-ahead action records.
7. Verify rule removal and persist RESTORED. If release is interrupted, reconcile actions on restart and retain conservative status.

Any rollback or verification failure skips network release entirely and preserves the recovery record. A restored pre-existing third-party dinput8.dll may preserve user data but prevents verified online restoration; keep isolation and explain the conflict. Do not delete that DLL automatically. Rule-release errors leave a recovery-required state even if files have been restored. Never remove legacy or another installation's rules incidentally.

## Legacy recovery

Inspect pc-changes.txt, sc-offline.installed, known backups, actual owned-rule candidates, and DLL contents. Legacy records lack reliable installation identity and cannot be automatically transferred to the selected installation. Before any legacy restoration, establish verified blocking for the explicitly selected installation. Only adopt legacy actions whose paths and ownership can be established; ambiguous shared records, hashes, or rules require recovery. Keep legacy blocking until all affected recorded installations are resolved. Report conservative migration instructions instead of guessing.

## CLI, GUI, and configuration

Replace Safe to go online with Restoration verified for the recorded installation, or Offline isolation verified while dirty and blocked. Other states are Recovery required and State unknown, with concrete unresolved conditions. This is verification of the launcher's recorded changes, not a promise of official-service compatibility or a scan of all game files.

Status uses observed state. Inaccessible files/journals, failed hashes, malformed records, unresolved backups, mismatched rules, or restored third-party DLLs cannot yield a success banner. List every known dirty installation so switching the displayed path cannot hide another transaction. Helper errors propagate to CLI exit status and GUI results; status returns nonzero for recovery-required/unknown state.

Update launcher documentation, shipped INI comments/defaults, CLI help, Linux guidance, and migration notes together. Keep session logs for diagnosis; their deletion is not part of restoration verification.

## Validation and acceptance

Use an injectable filesystem/firewall/process adapter to exercise real lifecycle decisions, not source-text assertions. Inject failure before and after each mutation and journal persistence boundary. Restart recovery from every durable state and from damaged records. Assert that rule removal never occurs after failed rollback or verification.

Cover persistent install and subsequent play/uninstall, missing/locked DLL, XML restore failure, marker/journal errors, conflicting EAC backups, shared-state contention, restored third-party DLL, changed install identity, two installs, stale/altered rules, disabled profiles/service, group-policy restrictions, and companion processes outliving the game. Verify rejected network configuration and restricted multiplayer address/port policy.

Build the native Windows launcher with the repository-supported MSVC toolchain and run applicable existing checks. Perform elevated firewall integration tests only with disposable executables and controlled endpoints, recording exact rules and TCP/UDP IPv4/IPv6 results. Test persistence across restart where the available environment allows it. Do not connect to CIG or run the game to validate these changes. Report unrun integration cases explicitly; a successful build or unit test does not prove runtime isolation.

## Limits

This protects the managed lifecycle, assuming the host firewall and local administrator remain trustworthy. It cannot guarantee safety against external policy changes, separate uploading applications, manual removal of protection, or uncontrolled persistent launches. Restoring recorded files does not prove the entire game installation is official or ban-safe.
