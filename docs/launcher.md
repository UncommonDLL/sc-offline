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

The production store and recovery files require Administrators/System ownership and write access, with read access for status. Existing untrusted owners or writable evidence are refused, including descendants. New staged recovery files receive protected ownership before any bytes are written. Journals use bounded, versioned, checksummed records; writes are staged, flushed, and atomically replaced. Original file hashes, verified backups, replacement hashes, rule ownership, and action intents/completions support recovery after interruption. Installation aliases are canonicalized; changed directory identities and reparse arrangements are rejected.

A missing, damaged, unreadable, or contradictory journal is unknown/recovery-required, not evidence that nothing changed. Do not manually delete recovery records or firewall rules to clear a banner. Review the specific error, resolve the conflict, and rerun Uninstall. Locked files, changed originals, failed XML restoration, missing backups, unresolved companion processes, or conflicting shared EAC state prevent network release.

EAC changes preserve the exact executable in the protected recovery store instead of overwriting an `.exe.bak`. The executable is removed while the recorded transaction is modified and restored from verified original bytes. Existing `.bak` files are conflicts. Hosts edits are journaled; concurrent edits conflict instead of being silently overwritten. An EAC download-host mapping is separate from network isolation, and executable absence does not prove all anti-cheat components are inactive.

## Legacy installations

Old `pc-changes.txt`, `sc-offline.installed`, and `.sc-offline-backup` evidence is not adopted as a clean baseline. A new installation attempt first establishes blocking for its explicitly selected path, then quarantines legacy ambiguity without deleting old rules/records. An unrecorded installed sc-offline DLL is similarly refused. Legacy shared ownership cannot be inferred from a rule name; manually reconcile the old transaction with its originals while keeping blocking, rather than using the new restore command to guess.

The new Uninstall only restores its valid transaction. Unresolved legacy evidence prevents successful verification. Existing third-party `dinput8.dll` files are preserved/restored, but they keep isolation and recovery-required status because a loadable modification remains.

## Status labels

- **Offline isolation verified**: modified transaction with currently matching observed rules, installed file hashes, and original recovery backups. Shared EAC backup conflicts prevent this claim. It does not authorize official play.
- **Restoration verified**: recorded originals match, unresolved mod/legacy conditions are absent, required processes are closed, and owned rules are absent.
- **Recovery required**: a known unfinished or conflicting transaction.
- **State unknown**: no valid evidence sufficient for the claim, including a never-managed installation.

These labels replace “Safe to go online.” The launcher does not scan or certify the complete official game installation.

## Wine and Linux

Play/install are disabled until a supported host isolation adapter can enforce the same contract. The Linux script also refuses restoration requiring native Windows policy verification. Status/help/update remain available where Wine supports them. A hosts entry alone is insufficient.

## Logs, updates, and plugins

Session logs remain available for diagnosis. The existing optional crash-report bundle and log-cleanup prompts are separate from restoration; deleting logs is not a safety control. GitHub update digest/manifest verification, plugin selection, and game feature behavior remain on their existing paths. See [features](features.md), [plugin UI](plugin-ui.md), and [build instructions](build.md).

## Other launcher features

### The Plugins page

The page manages `data\plugins\<id>\` the way the host (sco-core) reads it, with no separate list of its own:

- **What is listed**: every folder under `data\plugins` that holds a `plugin.ini` (a folder without one is skipped,
  as the host does), with its `name`, `version` and `author`; `description`, when a plugin adds one, is the
  tooltip. Folders are rescanned every 3 seconds.
- **On / off**: the switch creates or deletes an empty file named `disabled` in the plugin's folder. The host
  reads that marker when the game starts, so a change applies at the next start. The old `data\mods\mod.txt` /
  `enabled.txt` split is gone: nothing here reads or writes it.
- **The creative plugin** (`creative`: noclip, god mode, infinite ammo) ships with its `disabled` marker, so it
  starts **off**: switch it on here (and have `plugins = on`). A self-update copies every file in the release,
  that marker included, so switch it on again if it is off after an update.
- **Plugins are off**: the host loads no plugin unless `plugins = on` in `sc-offline.ini` (the default is on).
  When it is off, the page says so and **Turn on** writes the key.
- **Settings** (the gear, for a plugin whose `plugin.ini` has a `[settings]` section): edits the values the
  plugin declared (`bool`, `int`, `float`, `string`, `enum(...)`), checked against the declared range and
  choices with the host's rules. **Save** writes them where `sco.settings` keeps them: the plugin's own database
  `data\storage\<id>.db`, table `sco_kv`, key `sco.settings.<name>`, value `<type>:<value>`. **Reset** deletes the
  kept values, so the defaults apply. The fields are read-only while the game or a command is running: the host reads
  its settings once, at start, so a write during a session would not be seen and no `settings.changed` would fire.
  Close the game, edit, start it again. A plugin whose `[settings]` this page can't read is flagged; run
  `sco-plugin-check` on it.
- **Reload**: only shows a note. Hot reload runs inside the game, through its `sco.reload` command; the launcher
  has no channel into the running game to call it.

### Updates

On `play` and `status` the launcher asks GitHub for the newest release of `scubamount/sc-offline`
(3-second timeout; no network just skips it). With `update_channel = stable` (the default) only full
releases are offered; `update_channel = prerelease` also offers pre-releases (test builds). Drafts, older
versions and tags that aren't plain numbers are never offered. If a newer one exists, `play` asks
**"Update now?"** and `status` tells you to run `sc-offline.exe update`. It won't update while
`StarCitizen.exe` is running.

An update:
1. checks there's free disk space, then downloads `sc-offline-<tag>.zip`. The download only times out when
   it stalls, and is tried once more. The zip's SHA-256 must match the `digest` GitHub publishes for that
   asset; a mismatch or a missing digest stops it with nothing changed;
2. unpacks it with Windows' own `tar.exe` and checks it against its `manifest.json` (see below). Any
   problem stops it with nothing changed;
3. stages the listed files in `data\update\staged\`. This runs with normal rights. When the install folder
   isn't writable (Program Files), it stages in `%LOCALAPPDATA%\sc-offline\update\` instead, and only the
   next step asks Windows for administrator rights. That step uses no network: it checks every staged
   file against the manifest again before using it;
4. replaces every listed file except `sc-offline.ini` and the player files in `data\` (`wallet.txt`,
   `spawn.txt`, `bookmarks.txt`, `locations_found.txt`, `game-path.txt`, `game-build.txt`, the logs).
   `data\storage\` (your saves) is never in a release, so an update doesn't touch it.
   Each file is written as `<name>.update-new`, flushed to disk, the old one renamed to `<name>.update-old`,
   and the new one moved into place and checked again. Each step is written to `data\update\applied.txt`
   before it happens. A file that antivirus is scanning is retried for a few seconds;
5. appends settings that are new in the release's `sc-offline.ini` to yours, commented out, so their
   defaults apply;
6. runs `sc-offline.exe --self-test` from the new files, then starts the new launcher with the same arguments.

If a step fails, or the new launcher fails its self-test, the old files are put back at once. If the PC dies
mid-update, the next run of `sc-offline.exe` reads `applied.txt` and puts them back. The `.update-old` files
are deleted on the next good start. `check_updates = off` turns the check off; `sc-offline.exe update`
checks on demand.

#### What an update is checked against

Two things vouch for an update. Neither is a signature: releases aren't code-signed.

1. **GitHub's digest.** GitHub publishes a SHA-256 `digest` for every release asset, served over HTTPS
   from `api.github.com`. The downloaded zip must match it.
2. **`manifest.json` inside the zip.** CI writes it when it builds the release: the `version`, the `tag`,
   the `commit` it was built from, and every other file in the zip with its `sha256` and `size`, one per line.
   Its version must equal the release tag. Only files it lists are copied, and only when their SHA-256 matches.
   A listed path with `..`, a leading `/`, a `\` or a `:` makes the whole update fail.

So the update is exactly what CI built from that commit, as long as the GitHub release itself is
trustworthy. Anyone who can publish a release on `scubamount/sc-offline` can publish an update.

#### Checking a release by hand

On Windows (PowerShell), in the folder you downloaded the zip to:

```powershell
# 1. The zip against GitHub's digest (shown on the release page next to the asset, or:)
#    gh release view v0.7.0 -R scubamount/sc-offline --json assets --jq '.assets[] | [.name, .digest]'
(Get-FileHash .\sc-offline-v0.7.0.zip -Algorithm SHA256).Hash.ToLower()

# 2. Every unpacked file against manifest.json
Expand-Archive .\sc-offline-v0.7.0.zip -DestinationPath .
$dir = '.\sc-offline-v0.7.0'
$man = Get-Content "$dir\manifest.json" -Raw | ConvertFrom-Json
"$($man.tag) from commit $($man.commit), $($man.files.Count) files"
foreach ($f in $man.files) {
  $p = Join-Path $dir $f.path
  if (-not (Test-Path $p)) { "MISSING  $($f.path)"; continue }
  if ((Get-FileHash $p -Algorithm SHA256).Hash.ToLower() -ne $f.sha256) { "CHANGED  $($f.path)" }
}
```

No output after the summary line means every listed file matches. A file in the folder that the manifest
doesn't list (other than `manifest.json`) isn't part of the release. With Python (macOS, Linux or Windows),
`python3 tools/release-manifest.py check sc-offline-v0.7.0` from a clone of this repository does step 2,
also flags unlisted files, and exits non-zero on any problem. The `commit` field lets you
look up the exact source at `https://github.com/scubamount/sc-offline/tree/<commit>`.

### Discord status

The Discord status is a plugin, `data\plugins\discord` (source: `plugins/discord/`), built only from the sco SDK's
headers. With the Discord app open on the same PC it shows, while the game runs:

- **Playing sc-offline**, with where you are (the moon, planet or station) and the ship you're aboard
- the version the running mod reports (`sc-offline v<version>`), and the time played
- the sc-offline logo, and two buttons other people can click: **Join the Discord** and **Get sc-offline**

Every value is read from the running game, so the status always names the version you are actually playing. The plugin
talks only to the Discord app on your PC (its local pipe). It sends nothing over the network, and it needs no Discord login
or token. The status clears when the game closes. If Discord isn't running, nothing happens and `mod.log` says
`[discord] Discord isn't running`; if Discord starts later, the plugin picks it up within 15 seconds. Under Wine or Proton
the Discord pipe usually isn't reachable, so nothing is shown.

Its settings (where you are, your ship, the buttons) are on the plugin's page in the game's menu. To turn the status off,
switch **Discord** off in the window's top bar or on the **Plugins** page (both create `data\plugins\discord\disabled`).
The change applies from the next **Play**. An old `discord_presence = off` in `sc-offline.ini` is carried over: the first
0.7.5 run turns the plugin off and removes the line.

### Crash reports

If the game wrote crash files under `<channel>\Crashes` during the session, the launcher offers a report
before the log cleanup. A **y** zips `mod.log`, `launcher.log`, `Game.log` and the crash folder's text
files into `data\crash-reports\sc-offline-crash-<time>.zip`. In the copies (never the originals), your RSI
handle becomes `<handle>`, GEID and account numbers become `<id>`, and your Windows user name in paths
becomes `<user>`. Memory dumps (`.dmp`) are left out because they can't be redacted. It can then open the bug
form with the version, game build and platform filled in, and an Explorer window on the zip. **Nothing is
uploaded**: you attach the zip and read it first. `crash_reports = off` turns this off.

### Session logs

When the game closes, the launcher lists the logs the game wrote during this session: `<channel>\Game.log`,
new files in `<channel>\logbackups`, and new files under `<channel>\Crashes`. It asks **"Delete these
files?"** and then **"Are you sure?"**; anything but `y` both times keeps them. Files older than the session
(for example from online play) are never touched, and neither are `data\mod.log` and `data\launcher.log`.
Keep `Game.log` if you want to report a bug. Set `clean_logs = off` in `sc-offline.ini` to skip the question.
## `sc-offline.ini`

Each line is `key = value`. Lines starting with `#` are comments. An unknown key is reported when the launcher starts, not silently ignored.

There is no wallet setting: your aUEC balance is kept in `data\storage\contracts.db` and `data\wallet.txt`, which you can edit (see [Features](features.md#player)).

| Key | Default | Meaning |
| --- | --- | --- |
| `game` | (found automatically) | Your Star Citizen folder. You can point at `Roberts Space Industries`, at `StarCitizen`, at the channel folder, or at the folder that holds `StarCitizen`. |
| `check_updates` | `on` | Check GitHub for a newer release on `play` and `status` and offer to install it. |
| `update_channel` | `stable` | `stable`: only full releases are offered. `prerelease`: pre-releases (test builds) are offered too. |
| `crash_reports` | `on` | After a crash, offer a redacted log bundle and the bug form. See [Crash reports](#crash-reports). |
| `clean_logs` | `ask` | After the game closes, list this session's game logs and ask (twice) before deleting them. `off` skips it. |
| `channel` | `LIVE` | Which install to use when `game` points above it: `LIVE`, `PTU`, `EPTU`, and so on. |
| `boot_map` | `PU_All` | `PU_All` loads every star system, so Travel can reach Pyro and Nyx. |
| `start_ship` | `DRAK_Cutlass_Black` | The ship used by `start = Daymar`. **Without `start = Daymar` it does nothing.** |
| `start` | (empty) | Empty: the game's own spawn (Orison with `boot_map = PU`, a Pyro station with `PU_All`). `Daymar`: about 10 seconds after you spawn, `start_ship` is spawned over Daymar and you're put in its pilot seat. |
| `plugins` | `on` | `on`: load plugins from `data\plugins\<id>\`. See [Plugins](features.md#plugins). |
| `asop_fleet_list` | `ships` | Which ship list the terminals show with `asop = on`: `game` (the game's own; offline its entitlement query fails, so it's empty) or `ships` (every ship in `data\ships.txt`). |
| `mining` | `off` | `on`: natural mining, the rocks of the nearby ecosystem cells are built as the game does online. Experimental. See [Natural mining](features.md#natural-mining). `mining_debug = on` (default `off`) adds its counters to `mod.log`. |
| `asop` | `on` | `off`: leave the ship terminals, personal hangars, the hangar lift and ATC hails as the game has them offline. See [Ship terminals, hangars and ATC](features.md#ship-terminals-hangars-and-atc). |

Network and recovery settings are described above; EAC originals now use the protected recovery store.

## Validation

Standalone native tests: configure `tests/launcher_safety` with MSVC x64, build, then run CTest. They exercise transaction failures, native temporary-file recovery, corrupted journals, persistent policy changes, and compiled peer/port predicates without modifying a real game installation.

`windows_integration_tests --exercise-rules <evidence-file>` and `--exercise-multiplayer <evidence-file>` require elevation and operate only on the test executable's own rules. `--cleanup <evidence-file>` retries its journaled cleanup. These adapter checks prove rule representation, verification, disabled-rule rejection, and owned-rule removal. They do not by themselves prove off-host traffic blocking. Separate controlled-peer TCP/UDP IPv4/IPv6 and reboot tests remain required before treating the build as runtime accepted. Never use official services as test endpoints.
