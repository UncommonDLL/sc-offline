# Offline Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking. Execution method awaits user selection.

**Goal:** Ensure managed modified installations remain isolated until all restoration postconditions are verified.

**Architecture:** Extract the launcher's safety lifecycle into a small transaction engine with injectable host operations. A Windows adapter owns durable storage, installation identity, firewall policy, process checks, and verified file operations. CLI helpers and GUI consume the same observed transaction status.

**Tech Stack:** C++20, MSVC x64, Windows Firewall COM interfaces, Windows filesystem/process/service APIs, CMake/CTest, existing Python repository checks. No new runtime service or external network dependency.

**Spec:** ../specs/2026-10-11-offline-isolation-design.md

## Global Constraints

- All install/play operations require isolation.
- Default multiplayer to off in both compiled defaults and the shipped INI.
- Any rollback or verification failure skips network release entirely and preserves the recovery record.
- Missing or malformed records should mean state unknown, requiring inspection.
- Wine install/play is refused until a supported host isolation adapter exists.
- Preserve unrelated game hooks and plugin behavior.
- Do not connect to CIG or run the game to validate these changes.
- Local build and testing are authorized; publication and interaction with official services are outside this implementation.

## Review Focus

1. Junction/path aliases or a recreated installation directory must not adopt an old transaction (Tasks 1, 6).
2. Disk-full or partial journal writes must leave the last valid record available (Task 2).
3. Local firewall rules suppressed by policy must not be reported as enforced (Tasks 3, 8).
4. A second launcher/helper must not restore shared EAC state belonging to the first (Tasks 2, 6).
5. An error inspecting companion processes must prevent network release (Tasks 4, 8).

## File map

Create `launcher/safety/transaction.h/.cpp` for states and lifecycle; `journal.h/.cpp` for serialization and durable storage; `firewall.h/.cpp` for rule compilation and COM inspection; `windows_host.h/.cpp` for native file/process/shared-state adapters. Keep these separate from ImGui.

Create `tests/launcher_safety/CMakeLists.txt`, `test_support.h`, `transaction_tests.cpp`, `journal_tests.cpp`, `firewall_tests.cpp`, `recovery_tests.cpp`, and `windows_integration_tests.cpp`. The standalone test project avoids pulling in game-hook dependencies. Tests use a small assertion runner returning nonzero on failure; no fetched test framework.

Modify `launcher/launcher.cpp`, `launcher/sc-offline.ini`, `launcher/sc-offline.sh`, `CMakeLists.txt`, `.github/workflows/build.yml`, `docs/launcher.md`, and `docs/linux.md`. Launcher files are source assets; release-root copies are generated artifacts and should not be edited independently.

## Shared interface contract

Namespace `sco::safety`. `State` has Preparing, Isolated, Modified, Restoring, FilesRestored, ReleasePending, Restored, RecoveryRequired, Unknown. `Operation` has Install, Play, Restore. `Result` contains `bool ok`, `State state`, and `std::vector<std::string> issues`.

`InstallId` contains `std::wstring canonicalBin`, `uint64_t volume`, and `std::array<uint8_t,16> directoryId`. `FileRecord` contains path, backupPath, existed, originalSha256, replacementSha256, and action completion. `RuleSpec` contains unique name, application, direction, action, profiles, protocol, localPorts, remotePorts, remoteAddresses, enabled. `Journal` contains formatVersion, install, transactionId, mode, state, file records, rule records, shared-change records, and action intents/completions. Define exact serialization field names in Task 2 and keep them stable thereafter.

`Host` exposes virtual operations returning `Result`: `Load(Journal&)`, `Save(const Journal&)`, `Acquire(const InstallId&)`, `InspectProcesses()`, `EnsureIsolation(Journal&)`, `VerifyIsolation(const Journal&)`, `InstallFiles(Journal&)`, `RestoreFiles(Journal&)`, `VerifyRestoration(const Journal&)`, `ReleaseRules(Journal&)`; destructor is virtual. Functions `Prepare(Host&, Journal&)`, `Restore(Host&, Journal&)`, and `Observe(Host&, const Journal&)` return Result. WindowsHost implements Host; test FakeHost has failure injection, a modeled filesystem/rule store, and an action trace.

Tests below use `Fixture`, defined in Task 1: members `FakeHost host`, `Journal journal`; methods `Result install()`, `Result restore()`, `Result observe()`, `void fail(const char* operation)`, `void restart()`, `size_t releases()`, `bool blocked()`. Failure names are exact Host operation names above. `restart()` clears volatile state and reloads the durable journal while retaining modeled files and rules. `Require(bool)` throws a test failure; the test runner catches and reports failures.

## Task 1: Testable lifecycle and installation identity

**Files:** transaction.h/.cpp, windows_host.h/.cpp, standalone test CMakeLists.txt, test_support.h, transaction_tests.cpp.

**Interfaces:** Produce State/Result/InstallId/Journal/Host and Fixture as defined above. Produce `Result ResolveInstall(const std::wstring& bin, InstallId& out)` using GetFinalPathNameByHandleW and FileIdInfo. Fail for unresolved paths or identity mismatch; explicitly reject unsupported reparse arrangements.

- [ ] Add the assertion runner, Fixture/FakeHost, and the following regression test, then run it before implementing Restore:

```cpp
void failed_restore_keeps_isolation() {
    Fixture f;
    Require(f.install().ok);
    f.fail("RestoreFiles");
    Require(!f.restore().ok);
    Require(f.blocked());
    Require(f.releases() == 0);
}
```

- [ ] Configure `cmake -S tests/launcher_safety -B build/safety -G "Visual Studio 17 2022" -A x64`; build Debug and run `ctest --test-dir build/safety -C Debug --output-on-failure`. Missing lifecycle implementation must fail linkage/test; do not count a configure failure as the expected regression failure.
- [ ] Implement the minimal engine: Acquire -> EnsureIsolation -> VerifyIsolation -> InstallFiles for preparation; restoration never calls ReleaseRules unless RestoreFiles and VerifyRestoration succeed. Save required state transitions through Host. Any failed Save aborts progression.

```cpp
// In Restore, preserve the first actionable failure.
auto restored = host.RestoreFiles(journal);
if (!restored.ok) return restored;
auto verified = host.VerifyRestoration(journal);
if (!verified.ok) return verified;
// Persist FilesRestored/ReleasePending before ReleaseRules.
```

- [ ] Add tests for failed VerifyRestoration, inaccessible identity, alias equivalence, replaced directory identity, and failed process inspection. Run the native test project; commit the tested engine/identity foundation.

## Task 2: Write-ahead journal, backups, and shared ownership

**Files:** journal.h/.cpp, windows_host.h/.cpp, journal_tests.cpp, test_support.h.

**Interfaces:** Produce `Result EncodeJournal(const Journal&, std::string&)`, `Result DecodeJournal(std::string_view, Journal&)`, `Result SaveJournal(const std::wstring&, const Journal&)`. Use a versioned length-prefixed UTF-8 format with bounded lengths/counts and a SHA-256 checksum; reject trailing bytes, duplicate action IDs, invalid enum values, and absolute paths inconsistent with the recorded installation/shared locations. A journal is data, never an executable command.

- [ ] Write tests for truncation, checksum mismatch, unsupported version, non-ASCII paths, duplicate actions, and partial replacement. Model disk-full and locked destination conditions.

```cpp
void failed_journal_write_preserves_previous_record() {
    Fixture f;
    Require(f.install().ok);
    f.fail("Save");
    Require(!f.restore().ok);
    f.restart();
    Require(f.journal.state != State::Restored);
    Require(f.blocked());
}
```

- [ ] Run journal tests to confirm they fail for each injected durability defect. Implement temp-on-same-volume writes, FlushFileBuffers, atomic replacement/write-through, restricted ProgramData ACLs, and verified backup creation before mutation. Do not overwrite a conflicting backup.
- [ ] Implement Acquire with a machine-wide mutex plus a persisted shared-state ownership record; write intent for rule/file/hosts/EAC operations before calling the OS. Record hashes and exact paths for each backup. Persist completion only after inspecting postconditions.
- [ ] Exercise interruption before and after each mutation and restart; a second transaction must fail while shared state is owned by a dirty install. Run CTest and commit the durable journal/ownership implementation.

## Task 3: Exact firewall policy and restricted multiplayer

**Files:** firewall.h/.cpp, windows_host.h/.cpp, firewall_tests.cpp, standalone test CMakeLists.txt.

**Interfaces:** Produce `Result BuildPolicy(const InstallId&, const std::vector<std::wstring>& applications, const std::vector<uint32_t>& peers, const std::vector<uint16_t>& ports, std::vector<RuleSpec>& out)` and `Result VerifyPolicy(const std::vector<RuleSpec>&)`. Empty peers/ports selects full IPv4/IPv6 blocking. Require both nonempty for multiplayer; maximum 8 explicit IPv4 peers and 8 ports, no broadcast/multicast/unspecified/loopback peers, no CIDRs. Sort/deduplicate; reject invalid values rather than widening access.

- [ ] Add pure rule-compiler tests checking that all traffic is blocked except selected UDP tuples. Tests evaluate compiled rule predicates for chosen peer, neighboring peer, TCP, UDP wrong port, inbound/outbound, and IPv6.

```cpp
void unverified_policy_prevents_file_changes() {
    Fixture f;
    f.fail("VerifyIsolation");
    Require(!f.install().ok);
    Require(f.host.installedFileCount == 0);
}
```

- [ ] Implement peer-address complement ranges and port complements. Block TCP and other protocols fully, UDP to non-peer addresses fully, and UDP to selected peers except selected ports. Inbound exceptions use local ports; outbound exceptions use remote ports. Block all IPv6. Add only narrowly required inbound allows and verify their exact properties.
- [ ] Use INetFwPolicy2/INetFwRules/INetFwRule, CoInitializeEx and RAII COM handles; link ole32/oleaut32. Inspect service state, enabled profiles, local-policy modification state, and rule properties. Compare normalized sets, not localized printed output. Unsupported enforcement states fail closed. Use installation/transaction-specific rule names and group ownership.
- [ ] Add stale path, disabled rule, action/profile/scope mismatch, local-policy suppression, and duplicate-rule tests. Run CTest and commit policy compilation/verification.

## Task 4: Verified native installation and restoration

**Files:** windows_host.h/.cpp, transaction.cpp, transaction_tests.cpp, recovery_tests.cpp.

**Interfaces:** Implement InstallFiles/RestoreFiles/VerifyRestoration/InspectProcesses/ReleaseRules from Host; all issue lists name the affected path/rule/component. Produce process observation with canonical executable identity, distinguishing absent from inspection failure.

- [ ] Write tests for partial DLL copy, locked DLL removal, XML restore/deletion failure, missing backup, original hash mismatch, conflicting EAC .exe/.bak, failed hosts restoration, and third-party DLL restored from backup.

```cpp
void failed_verification_never_releases_rules() {
    Fixture f;
    Require(f.install().ok);
    f.fail("VerifyRestoration");
    auto r = f.restore();
    Require(!r.ok && r.state != State::Restored);
    Require(f.releases() == 0);
}
```

- [ ] Run failures first. Implement exact original-presence/hash checks, no overwrite of unknown files, and tracked DLL/XML/EAC/hosts rollback. An original third-party DLL prevents verified online restoration even after successful replacement; explain that without deleting it.
- [ ] Check game and discovered companion process lifetime before release; process-inspection errors block release. Persist each removal intent/completion, delete only owned exact-match rules, then verify absence and save restoration receipt. Failed release remains recovery-required.
- [ ] Add restart tests from FilesRestored and ReleasePending, including a new conflict before release. Run CTest and commit restoration adapter.

## Task 5: CLI/helper lifecycle, mandatory defaults, and supervision

**Files:** launcher/launcher.cpp, launcher/sc-offline.ini, launcher/sc-offline.sh, CMakeLists.txt, transaction_tests.cpp.

**Interfaces:** Replace PutMod/TakeMod/ApplyPcChanges/UndoPcChanges call paths with Prepare/Restore/Observe using WindowsHost. Preserve helper IPC but bind it to validated transaction/installation IDs. Add validated multiplayer peer/port configuration; reject legacy broad ranges with a migration error.

- [ ] Add tests that Install and Play share preparation, block_network=off stops before mutation, persistent Install retains rules, and a later Play revalidates its journal rather than backing up modded files as originals.

```cpp
void persistent_install_remains_blocked() {
    Fixture f;
    f.journal.mode = Operation::Install;
    Require(f.install().ok);
    f.restart();
    Require(f.blocked());
    Require(f.journal.state == State::Modified);
}
```

- [ ] Set both compiled and shipped multiplayer defaults off. Reject Wine install/play in launcher and wrapper; retain help/status and explicitly supported restoration behavior. Keep --skip-eac-check unable to override isolation or journaling.
- [ ] Revalidate policy immediately before starting the game. Supervise the actual managed process while checking policy every second; detected failure requests process shutdown and then terminates the managed game if necessary, preserving recovery state. Do not terminate unrelated processes by basename alone. Check helper availability before launch and propagate supervision errors.
- [ ] Replace helper cleanup with Restore; propagate nonzero results through CLI and GUI. Persistent completion states that isolation remains and controlled Play is required. Build the launcher target and run lifecycle tests; commit lifecycle integration.

## Task 6: Legacy reconciliation and observed status

**Files:** journal.cpp, windows_host.cpp, launcher/launcher.cpp, recovery_tests.cpp.

**Interfaces:** Produce `Result InspectLegacy(const InstallId&, Journal&)` for conservative inspection, never blind adoption. Observe returns issues and actual state for GUI/CLI; enumerate known dirty installation journals from the restricted store.

- [ ] Add tests for selected install B with legacy rules for A, malformed pc-changes.txt, unreadable dinput8.dll, stale installed marker, missing marker with backup evidence, and two simultaneous dirty installation records.

```cpp
void unreadable_state_is_not_restored() {
    Fixture f;
    Require(f.install().ok);
    f.fail("Load");
    Require(f.observe().state == State::Unknown);
}
```

- [ ] Inspect legacy paths/rules/backups; establish new verified isolation for the explicitly selected install before restoring any unambiguous action. Ambiguous global changes/rules retain recovery-required state; do not delete them as housekeeping.
- [ ] Replace RefreshLight's marker-based decision and completion messages with shared Observe results. Use Restoration verified, Offline isolation verified, Recovery required, or State unknown. Display other dirty installations and concrete conflicts; return nonzero status for unknown/recovery-required.
- [ ] Run recovery tests, build launcher, and commit legacy/status integration.

## Task 7: Documentation and automated native checks

**Files:** docs/launcher.md, docs/linux.md, launcher/sc-offline.ini, launcher/sc-offline.sh, .github/workflows/build.yml, tests/launcher_safety/CMakeLists.txt.

- [ ] Add CLI/configuration compatibility tests alongside the changes they describe: forbidden block_network setting, removed CIDR exceptions, new explicit peer/port values, and Wine refusal.
- [ ] Document persistent isolation, controlled launch, journal recovery, legacy conflicts, third-party DLL handling, nonzero status, and the narrow meaning of Restoration verified. Explain that monitoring and persistent rules cannot guarantee safety against outside administrator changes or manual direct launches.
- [ ] Add a Windows CI job configuring/building the standalone safety project and running CTest without administrator rights. Keep existing release-manifest/SDK/build checks. Add no CI dependency on game files or official endpoints.
- [ ] Run `python tools/test_release_manifest.py`, `python tools/test_sdk_headers.py`, the safety CTest suite, and `git diff --check`; inspect failures rather than treating exit alone as evidence. Build the native launcher with initialized repository submodule when prerequisites are available. Commit docs/CI checks.

## Task 8: Controlled Windows firewall acceptance and final review

**Files:** windows_integration_tests.cpp, tests/launcher_safety/CMakeLists.txt; validation evidence in a user-facing report.

**Interfaces:** Integration executable modes `--server`, `--client`, `--policy-check`, and `--cleanup`, operating only on its own canonical path and unique test transaction. Use owned firewall test groups, loopback plus an explicitly supplied controlled peer. Never enumerate/select game installs or contact official endpoints. RAII plus a durable test journal makes cleanup retryable after failure.

- [ ] Implement socket probes for TCP/UDP IPv4/IPv6 and compare actual rule inspection with declared policy. Gate mutation mode on explicit test invocation and administrator availability. Save evidence of created/removed rule identities and observed connection outcomes.
- [ ] Test all-block mode, narrow multiplayer UDP, wrong peers/ports/protocol, tampered/disabled rules, and rules targeting a different executable. Test process-inspection failure with the fake adapter rather than disturbing real companion programs.
- [ ] Run elevated integration only with controlled endpoints available. Do not disable machine-wide firewall profiles for tests on the user's host; exercise those conditions via adapters or a disposable test environment. Reboot persistence is tested in a disposable environment when available; otherwise mark it unrun.
- [ ] Repeat fault/restart tests after final changes, inspect the complete diff against the approved specification, and record build, unit, integration, and unrun cases separately. Fix demonstrated defects and rerun affected checks. No implementation-complete claim until all five requested areas are implemented and required automated checks pass; runtime limits remain explicit.
- [ ] Commit final verified changes locally. Provide changed files, outcomes, residual limits, and a patch/deliverable in outputs. Remote push/PR publication requires the user's requested delivery scope; do not assume it from the fork URL alone.

## Execution handoff

The spec and plan require review before product code changes. Recommended approach: native execution in this chat because the lifecycle tasks share interfaces and one owner can keep those contracts consistent. User may instead choose subagent-driven implementation/review. During execution, use an isolated managed worktree where supported and provide progress updates plus observed validation evidence.
