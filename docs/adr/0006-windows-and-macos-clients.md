# 0006. Windows and macOS clients: services, local API transport, packaging

- Status: proposed
- Date: 2026-10-02
- Supersedes: the "Windows and macOS get a user-mode daemon only" consequence of ADR 0002

## Context

`porthole` already builds for windows/darwin (amd64, arm64) and the CI test matrix runs on `windows-latest` and
`macos-latest`, but on those systems it is only a foreground CLI plus a user-mode `porthole daemon` that nothing
starts at boot or login. The release ships zip/tar.gz archives only. ADR 0002 deferred a Windows service, a launchd
plist and named pipes. The goal now is a client that a Windows or macOS user (or an agent acting for them) can
install once and forget, with the same local API, MCP adapter and audit identity as on Linux.

Prior art (read with `gh api` on 2026-10-02; paths are in each repository's default branch):

- **tailscale** — `tailscaled` is a real Windows service (`cmd/tailscaled/tailscaled_windows.go`: `svc.IsWindowsService`,
  `svc.Run`, accepts stop/session-change/power events). `tailscaled install-system-daemon`
  (`cmd/tailscaled/install_windows.go`) uses `x/sys/windows/svc/mgr`: `StartAutomatic` and a ladder of
  `mgr.ServiceRestart` recovery actions. The LocalAPI on Windows is a named pipe created with go-winio
  (`safesocket/pipe_windows.go`) under `\\.\pipe\ProtectedPrefix\Administrators\` (`paths/paths.go`:
  "named pipe names that only administrators may create"), so no unprivileged process can squat the name; a
  per-user dev daemon listens on `\\.\pipe\tailscale-<SID>` with `O:<SID>D:P(A;;GWGR;;;<SID>)`, and the client
  refuses a pipe whose owner or DACL is not exclusively the current user. Peer identity: `GetNamedPipeClientProcessId`
  and the client's access token (`WindowsClientConn.ClientPID`, `Token`). macOS: `install-system-daemon` writes
  `/Library/LaunchDaemons/com.tailscale.tailscaled.plist` and drives `launchctl` (`cmd/tailscaled/install_darwin.go`);
  the GUI apps are separate, closed-source products.
- **moby (dockerd)** — `daemon/listeners/listeners_windows.go`: `winio.ListenPipe` on `\\.\pipe\docker_engine` with
  `D:P(A;;GA;;;BA)(A;;GA;;;SY)` plus `(A;;GRGW;;;<sid>)` for each extra user or group (the `docker-users` group is the
  Windows twin of the Linux `docker` group).
- **cloudflared** — `cloudflared service install` on every OS. Windows (`cmd/cloudflared/windows_service.go`):
  service `Cloudflared` via `svc.Run`, `svc/eventlog` for start/stop messages, config under `%ProgramData%`, the
  token file written with `O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)` (protected DACL: Administrators and SYSTEM only).
  macOS (`cmd/cloudflared/macos_service.go`): `com.cloudflare.cloudflared.plist` with `RunAtLoad`/`KeepAlive`, written to
  `~/Library/LaunchAgents` for a normal user and `/Library/LaunchDaemons` for root; logs in `~/Library/Logs` or
  `/Library/Logs`.
- **Caddy** — `service_windows.go`: `svc.IsWindowsService()` in `init`, then `svc.Run` with a minimal handler;
  installation is left to `sc.exe create` (documented), i.e. no install command.
- **ngrok** — `ngrok service install --config <file>` / `start` / `stop` / `uninstall` on Windows, macOS (launchd)
  and Linux (public agent docs; closed source).
- **frp** — no service support; users wrap `frpc.exe` in WinSW or NSSM (fatedier/frp#2468, #2227, #1901).
- **Syncthing** — no built-in service; docs (`syncthing/docs`, `users/autostart.rst`) recommend Task Scheduler or
  NSSM on Windows and a plist in `~/Library/LaunchAgents` (or `brew services`) on macOS.
- **kardianos/service** (Zlib, 4.8k stars) abstracts systemd/launchd/Windows services, but hides the parts that matter
  here (recovery actions, the account, the plist domain) and adds a dependency for ~400 lines we can own.

Go specifics:

- `net.Listen("unix")` works on Windows 10 1803+ (ADR 0002 relies on it), but: there is no `SO_PEERCRED`; the
  Windows equivalent `SIO_AF_UNIX_GETPEERPID` is not in `golang.org/x/sys/windows` and would need a raw `WSAIoctl`;
  access control is only the file/directory DACL; `os.Stat` on the socket file has had bugs (golang/go#57535);
  the path limit is 108 bytes.
- Named pipes: `golang.org/x/sys/windows` has `CreateNamedPipe`, `GetNamedPipeClientProcessId`,
  `ImpersonateNamedPipeClient`, SDDL parsing, but no `net.Listener`; `github.com/Microsoft/go-winio` (MIT) provides
  `ListenPipe`/`DialPipeContext` with overlapped I/O and an SDDL in `PipeConfig`, and is what tailscale, moby and
  containerd use.
- macOS: `getsockopt(LOCAL_PEERCRED)` (already in `internal/localapi/peercred_darwin.go`) gives UID/GIDs; the PID
  via `LOCAL_PEERPID`.

GoReleaser (OSS, `www/content/customization`): `homebrew_casks` (formulas are deprecated since v2.10), `scoops`,
`winget` (generates the manifest and opens a PR, to `microsoft/winget-pkgs` if configured) and `chocolateys` are in
OSS; `msi`, `nsis` and `pkg` installers are Pro-only. macOS signing and notarization work cross-platform in OSS via
anchore/quill (`sign/notarize.md`, "Cross-platform"); native notarization is Pro. Homebrew casks put the quarantine
attribute on downloads, so an unsigned binary is blocked by Gatekeeper unless the cask strips it (goreleaser docs
show an `xattr -dr com.apple.quarantine` post-install hook and warn that it bypasses macOS security).

## Decision

### 1. `porthole service install|uninstall|start|stop|restart|status`

One cross-platform command group (ngrok, cloudflared) instead of per-OS instructions (Caddy, Syncthing, frp). It
always manages the **system** service; `--user` selects the per-user variant where the OS has one.

| | Linux | macOS | Windows |
|---|---|---|---|
| system (default) | systemd unit `porthole.service` (the text of `deploy/porthole.service`, embedded) | `/Library/LaunchDaemons/io.github.eto-a.porthole.plist` | Windows service `porthole` (display name "porthole tunnel client") |
| `--user` | `~/.config/systemd/user/porthole.service` (from `deploy/porthole.user.service`) | `~/Library/LaunchAgents/io.github.eto-a.porthole.plist` | not supported (see below) |
| runs as | `porthole-client` (created by deb/rpm, or by `install` with `useradd --system`) | root (system) / the user (agent) | LocalSystem |
| command line | `porthole daemon` with explicit `--config/--tunnels` | same | same; the binary detects `svc.IsWindowsService()` |

- `install` writes the unit/plist/service, creates the config directory with the right permissions (§3), copies
  nothing (the binary must already be in its final place; `install` warns about a binary under a temp or `Downloads`
  directory and prints the path it registered), enables and starts it. Re-running `install` updates the definition
  (idempotent). `--config`/`--tunnels` may point elsewhere; the default is the system path of §3.
- `status` prints the service state plus `GET /v1/status` from the local API; `--json` as everywhere (ADR 0005).
- Linux: the unit text is the one in `deploy/` (embedded with `go:embed` from a tiny `deploy` package), so packages
  and `service install` cannot drift. `systemctl daemon-reload && systemctl enable --now`.
- macOS: plist keys `Label`, `ProgramArguments`, `RunAtLoad=true`, `KeepAlive={SuccessfulExit=false}` with
  `ThrottleInterval=10` (launchd cannot exclude an exit code like `RestartPreventExitStatus=78`, so a broken file is
  retried every 10 s and logged; `install` validates the files first), `ProcessType=Background`,
  `StandardOutPath`/`StandardErrorPath` in `/Library/Logs/porthole/` or `~/Library/Logs/porthole/` (cloudflared).
  Loading uses the modern `launchctl bootstrap system|gui/<uid> <plist>` / `bootout` / `kickstart -k`
  (tailscale and cloudflared still use the legacy `load`/`unload`). Reload: `porthole reload` over the API; launchd has
  no reload hook and the daemon already handles SIGHUP.
- Windows: `x/sys/windows/svc/mgr` with `StartAutomatic` + `DelayedAutoStart`, recovery actions restart after 1 s,
  5 s, 30 s with a 1-day reset (tailscale's ladder, shortened), `ErrorControl: Normal`. The daemon runs inside
  `svc.Run` (Caddy/cloudflared pattern): `StartPending` → `Running` once the pipe listens and the file is loaded
  (the same point where Linux sends `READY=1`), `Stop`/`Shutdown` cancel the daemon context, `ParamChange`
  (`sc control porthole paramchange`) triggers a reload — Windows' SIGHUP. An event-log source `porthole`
  (`svc/eventlog`, registered by `install`) gets start/stop/fatal messages only; the full slog stream goes to
  `%ProgramData%\porthole\logs\porthole.log`, size-capped with one rotated copy.
- **LocalSystem, not a virtual account.** A virtual account (`NT SERVICE\porthole`) would be the least-privilege twin
  of the Linux `porthole-client` user, but it cannot create a pipe under `ProtectedPrefix\Administrators`, and a pipe
  outside that prefix can be squatted by any local user before the service starts unless every client verifies the
  owner SID. LocalSystem is what tailscale, moby, cloudflared and Caddy (via `sc create`) use. Moving to a virtual
  account with client-side owner checks (tailscale `connectCurrentUser`) is a recorded follow-up, not part of this
  step.
- **No Windows `--user` service.** Windows has no per-user service manager comparable to systemd user units or
  LaunchAgents (per-user services are templates, Task Scheduler is a different model — Syncthing's docs). A user who
  does not want a system service runs `porthole daemon` in a terminal or adds it to Task Scheduler; a documented
  `schtasks` recipe goes into the docs instead of code.
- `install`/`uninstall` need elevation (root/Administrator, `--user` excepted); without it they fail with a hint
  and never self-elevate (no UAC prompt from a CLI that agents call).

### 2. Local API transport and peer identity per OS

| | Linux | macOS | Windows |
|---|---|---|---|
| transport | unix socket (unchanged) | unix socket (unchanged) | **named pipe** (go-winio) |
| system endpoint | `/run/porthole/porthole.sock`, dir 0750 group `porthole-client` | `/var/run/porthole/porthole.sock`, dir 0700 root (clients use `sudo`) | `\\.\pipe\ProtectedPrefix\Administrators\porthole` |
| user endpoint | `$XDG_RUNTIME_DIR/porthole/porthole.sock` | `~/Library/Caches/porthole/porthole.sock` (unchanged) | `\\.\pipe\porthole-<user SID>` |
| access | file mode + group | file mode (root only) | DACL, below |
| peer identity | `SO_PEERCRED` (uid, gid, pid) | `LOCAL_PEERCRED` + `LOCAL_PEERPID` | `GetNamedPipeClientProcessId` + `ImpersonateNamedPipeClient`/`OpenThreadToken` → user SID and name |

Windows pipe instead of the AF_UNIX socket ADR 0002 chose, because:

1. **Peer identity.** The audit log (ADR 0005) needs the acting user. Pipes give the client PID and token through
   `x/sys/windows`; AF_UNIX on Windows gives nothing without a hand-written `SIO_AF_UNIX_GETPEERPID` ioctl plus
   `OpenProcess` on another user's process.
2. **Atomic ACL and no squatting.** The pipe's DACL is set at creation from an SDDL, and the system name lives under
   `ProtectedPrefix\Administrators` where only administrators can create pipes (tailscale). An AF_UNIX socket's
   protection is the DACL of `%ProgramData%\porthole`, which must be created and locked before anyone else creates it
   (`%ProgramData%` is writable by Users by default).
3. **Precedent.** tailscale, moby/dockerd and containerd all serve their Windows control API over a pipe with
   go-winio; none uses AF_UNIX for it. No stale-file cleanup, no 108-byte limit, no `os.Stat` quirks.

DACLs (moby style, generic-all for owners, read/write for admitted principals):

- system pipe: `D:P(A;;GA;;;SY)(A;;GA;;;BA)` plus `(A;;GRGW;;;<sid>)` for each `--allow <user-or-group>` given to
  `service install` (stored in the service's command line as `--allow`). The Windows twin of
  `usermod -aG porthole-client` is `net localgroup porthole-users <user> /add` + `--allow porthole-users`
  (dockerd `--group docker-users`).
- user pipe: `O:<SID>D:P(A;;GA;;;<SID>)` and the client verifies owner and DACL before talking (tailscale
  `listenCurrentUser`/`connectCurrentUser`), because names outside the protected prefix can be squatted.

The CLI search order stays `--socket`, `$PORTHOLE_SOCKET`, user endpoint, system endpoint; on Windows a value
starting with `\\.\pipe\` is a pipe, anything else is still accepted as an AF_UNIX path (tests, WSL interop). The
user-mode AF_UNIX path of v0.3 on Windows is dropped; the binary is the same, so client and daemon move together.

`localapi.Cred` gains `SID` and `User` (Windows, empty elsewhere) and `User` on Unix is resolved from the UID;
`peerAttrs` and the audit log record `User` when present. Write access policy does not change: whoever can open
the endpoint may mutate (ADR 0002), so the ACL is the policy.

New direct dependency: `github.com/Microsoft/go-winio` (MIT), Windows-only build tag.

### 3. Paths per OS

| | system | user |
|---|---|---|
| Linux | `/etc/porthole/{config,tunnels}.yaml`, journald | `$XDG_CONFIG_HOME/porthole/` (unchanged) |
| macOS | `/Library/Application Support/porthole/{config,tunnels}.yaml` (0750 root:wheel, config 0640), logs `/Library/Logs/porthole/` | `~/Library/Application Support/porthole/` (= `os.UserConfigDir`, unchanged), logs `~/Library/Logs/porthole/` |
| Windows | `%ProgramData%\porthole\{config,tunnels}.yaml`, `logs\` | `%AppData%\porthole\` (= `os.UserConfigDir`, unchanged) |

`%ProgramData%\porthole` is created by `service install` with a protected DACL
`O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` (cloudflared's token-file descriptor, made inheritable), plus read for
`--allow` principals on `tunnels.yaml` only — never on `config.yaml`, which holds the token. If the directory
already exists with a looser DACL, `install` resets it and says so. The 0600 check on `token_file` (ADR 0002) gets
a Windows twin: refuse a token file whose DACL grants read to anyone except SYSTEM, Administrators and the owner.
`porthole login --system` writes the system `config.yaml` (elevated); without it `login` keeps writing the user one.

### 4. Distribution

| channel | how | needs from the owner |
|---|---|---|
| Windows zip (exists) | goreleaser archives | — |
| Scoop | goreleaser `scoops` → bucket repo `eto-a/scoop-bucket` | create the repo; a fine-grained PAT secret with write to it |
| winget | goreleaser `winget` (zip with nested portable exe) → PR to `microsoft/winget-pkgs` from a fork | a fork + PAT; **each PR is an external publication — the owner approves it**; first submission goes through Microsoft review |
| Homebrew | goreleaser `homebrew_casks` → tap `eto-a/homebrew-tap` (`brew install eto-a/tap/porthole`) | create the repo + PAT secret |
| macOS signing/notarization | goreleaser `notarize.macos` with quill (OSS, runs on Linux) | **Apple Developer ID** ($99/year), the `.p12` and an App Store Connect API key as secrets |
| Windows Authenticode | goreleaser `signs`/`binary_signs` with an external signer | **a code-signing certificate** (OV/EV, or a hosted signer such as Azure Trusted Signing or the SignPath OSS program) |
| MSI / `.pkg` installers | not now: goreleaser Pro only; `service install` covers what an installer would do | — |
| Chocolatey | not now: a third moderated community repository with little extra reach over winget + Scoop | — |

Without the Apple ID the cask must strip the quarantine attribute (documented as a security trade-off) or users
download with `curl`/`brew` from the tap; without Authenticode, SmartScreen warns on browser downloads of the exe
(winget and Scoop installs are unaffected in practice). Sigstore/cosign signatures and GitHub attestations (already
produced) do not satisfy Gatekeeper or SmartScreen; they stay as the verifiable supply-chain proof.
Until the owner provides the accounts, the goreleaser blocks are present but `skip_upload: true` (or `disable`),
so the release keeps working. `install.sh` gains darwin support (it already detects the OS) but no
`service install`; that is a separate, explicit step.

### 5. Tests and CI

- Unit tests per OS: plist/unit/service-config rendering (golden files, all OSes), SDDL construction, path tables.
- Pipe tests (`internal/localapi`, Windows): user pipe round trip, a second user cannot open it (DACL check via
  `GetSecurityInfo`), peer PID and SID are the test process's, squatting check refuses a pipe with a foreign owner.
  They run without elevation on the dev box and on `windows-latest`.
- Service tests behind `PORTHOLE_TEST_SERVICE=1` (they change the machine): on `windows-latest` (runners are
  elevated) `porthole service install` → `status` shows Running and the API answers through the system pipe →
  `sc control porthole paramchange` reloads → `stop` → `uninstall` leaves no service, no event source. On
  `macos-latest`, `sudo porthole service install` (LaunchDaemon; GUI-domain agents need a login session that CI
  runners may lack, so `--user` is covered by the rendering test plus a `launchctl bootstrap gui/$(id -u)` smoke that
  is allowed to skip). On `ubuntu-latest`, `sudo porthole service install` against the runner's systemd.
- On the Windows dev machine the same test runs from an elevated terminal; it skips with a message when not elevated
  (checked via the process token's elevation).
- A new CI job `service (${{ matrix.os }})` runs only these tests and is not required in the `protect main` ruleset
  until it has been stable for a release.

### 6. Out of scope now

- **Tray / menu-bar app.** tailscale ships one, but its users are humans toggling a VPN; porthole's primary operators
  are agents via the CLI, the local API and MCP (ADR 0005), and a GUI would need a second toolkit (Wails/Fyne or
  native), its own signing story and per-OS packaging, while adding no capability the API lacks. Revisit for v0.5 as
  a separate binary that only talks to the local API, if users ask for it.
- MSI/pkg installers, Chocolatey, a Mac App Store or System Extension build (porthole needs no network extension).
- Running the Windows service under a virtual account (follow-up, see §1).

## Consequences

- One new dependency (go-winio, Windows only). `golang.org/x/sys` grows into `svc`, `svc/mgr`, `svc/eventlog`.
- Windows changes local API transport from AF_UNIX to named pipes; `--socket` with a plain path still works.
- The service on Windows runs as LocalSystem: a compromise of the client process is a compromise of the machine,
  as with tailscale and dockerd. Mitigated by the protected pipe, the protected `%ProgramData%\porthole` DACL and
  the follow-up to a virtual account.
- Publication to Homebrew, Scoop and winget and both signing paths wait for the owner's accounts and approval; the
  code and goreleaser config can land before that.

## Alternatives rejected

- AF_UNIX socket in `%ProgramData%\porthole` on Windows: no peer identity without raw ioctls, protection depends on
  winning the race to create the directory, no precedent in the reference projects.
- kardianos/service: hides the account, recovery and launchd domain choices we need to control.
- Leaving installation to `sc.exe`/NSSM/WinSW or hand-written plists (Caddy, Syncthing, frp): an agent cannot do it
  reliably and users get it wrong; ngrok and cloudflared show one command is expected.
- Loopback TCP for the local API on Windows/macOS: rejected for the reasons in ADR 0002.
- MSI via WiX outside goreleaser: a second toolchain on the release path for something `service install` already does.
