# Native Sliver vs this Sliver UI: RPC / command coverage

Scope: BishopFox Sliver operator surface (gRPC `SliverRPC`, sliver-client server + implant menus, current 1.5–1.7.x / master as of 2026-11) versus this fork at `/home/cup/Documents/personal/sliv`. Status labels: **implemented** (backend RPC wrap + first-class UI), **partial** (RPC wrap but thin flags / buried UI / session-only), **missing** (no wrap or no UI), **UI-only extra** (not in stock sliver-client). This UI is a gRPC *client* of an existing sliver-server, not a replacement teamserver.

Version pins used below:
- UI Go module: `github.com/bishopfox/sliver v1.7.3` — [backend/go.mod](file:///home/cup/Documents/personal/sliv/backend/go.mod)
- Local protobuf catalog: `/home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/protobuf/rpcpb/services.proto`
- Installed `sliver-client` on this machine: **v1.7.9** (`6cf3ad78…`, 2026-10-25) at `/usr/local/bin/sliver-client`
- Master RPC surface fetched 2026-11-16: [BishopFox/sliver/protobuf/rpcpb/services.proto](https://github.com/BishopFox/sliver/blob/master/protobuf/rpcpb/services.proto)

## What is the sliver-client command / RPC catalog?

### Takeaway
Stock Sliver exposes one gRPC service `SliverRPC` with **186 `rpc` declarations in v1.7.3** (sessions, beacons, generate, listeners/jobs, loot/creds/hosts, HTTP C2, traffic encoders, builders, crackstation, wasm, WG, tunnels, events, etc.). The console splits that into a **server menu** (jobs, generate, armory, crack, reactions, …) and an **implant menu** (filesystem, exec, privileges, pivots, wasm, cursed, …). Master (and the v1.7.9 client on this box) add **AI conversations**, **OPFOR CNA**, extra **crack job** RPCs, and `sliver-client mcp`.

### Cited Findings
- v1.7.3 `service SliverRPC` includes GetVersion, ClientLog, GetOperators, Kill/Reconfigure/Rename, GetSessions, MonitorStart/Stop/ListConfig/AddConfig/DelConfig, StartMTLS/WG/DNS/HTTP/HTTPSListener, GetBeacons/GetBeacon/RmBeacon/GetBeaconTasks/GetBeaconTaskContent/CancelBeaconTask/UpdateBeaconIntegrityInformation, GetJobs/KillJob/RestartJobs, StartTCPStagerListener, Loot*, Creds*, Hosts*, Generate/GenerateSpoofMetadata/GenerateExternal/GenerateExternalSaveBuild/GenerateExternalGetBuildConfig/GenerateStage/StageImplantBuild, GetHTTPC2Profiles/GetHTTPC2ProfileByName/SaveHTTPC2Profile, BuilderRegister/BuilderTrigger/Builders, GetCertificateInfo/GetCertificateAuthorityInfo, Crack/Crackstation*/CrackTask*/CrackFile*, Regenerate/ImplantBuilds/DeleteImplantBuild/Canaries/GenerateWGClientConfig/GenerateUniqueIP/ImplantProfiles/DeleteImplantProfile/SaveImplantProfile, ShellcodeRDI/GetCompiler/ShellcodeEncoder/ShellcodeEncoderMap, TrafficEncoderMap/Add/Rm, Websites*, Ping/Ps/Terminate/Ifconfig/Netstat/Ls/Cd/Pwd/Mv/Cp/Rm/Mkdir/Download/Upload/Grep/Chmod/Chown/Chtimes/Memfiles*/Mount/ProcessDump/RunAs/Impersonate/RevToSelf/GetSystem/Task/Msf/MsfRemote/ExecuteAssembly/Migrate/Execute/ExecuteWindows/ExecuteChildren/Sideload/SpawnDll/Screenshot/CurrentTokenOwner/Services/ServiceDetail/StartServiceByName, Pivot*, StartService/StopService/RemoveService, MakeToken/GetEnv/SetEnv/UnsetEnv/Backdoor/Registry*/RunSSHCommand/HijackDLL/GetPrivs/StartRportFwdListener/GetRportFwdListeners/StopRportFwdListener, OpenSession/CloseSession, RegisterExtension/CallExtension/ListExtensions, RegisterWasmExtension/ListWasmExtensions/ExecWasmExtension, WGStartPortForward/WGStopPortForward/WGStartSocks/WGStopSocks/WGListForwarders/WGListSocksServers, Shell/ShellResize/Portfwd, CreateSocks/CloseSocks/SocksProxy, CreateTunnel/CloseTunnel/TunnelData, Events — [v1.7.3 services.proto](https://github.com/BishopFox/sliver/blob/v1.7.3/protobuf/rpcpb/services.proto); local copy `/home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/protobuf/rpcpb/services.proto` (186 `rpc` lines).
- Master adds AI block `GetAIProviders`, `GetAIConversations`, `GetAIConversation`, `SaveAIConversation`, `DeleteAIConversation`, `GetAIConversationMessages`, `SaveAIConversationMessage`; crack-job block `CrackJobs`, `CrackJobByID`, `CrackJobCancel`, `CrackJobPause`, `CrackJobResume`, `CrackJobDelete`, `CrackTop`; and `CrackstationBenchmarks` — [master services.proto](https://github.com/BishopFox/sliver/blob/master/protobuf/rpcpb/services.proto).
- Server-menu command packages bound in v1.7.3: exit, serverctx, licenses, settings, alias, extensions, armory, update, operators, creds, crack, certificates, clean, aka; jobs, mcp, websites, wireguard, c2profiles, socks; shikata-ga-nai, shellcode-encoders, generate, builders; use, info, sessions, beacons, monitor, loot, hosts, reaction, taskmany — [client/command/server.go](https://github.com/BishopFox/sliver/blob/v1.7.3/client/command/server.go).
- Implant-menu command packages bound in v1.7.3: reconfig, sessions (sliver), kill, tasks, pivots, aka; info, screenshot, environment, registry, extensions; edit, hexedit, filesystem; network, rportfwd, portfwd, socks, wireguard; shell, exec, backdoor, dllhijack, cursed, wasm; privilege; processes; plus dynamically loaded aliases/extensions — [client/command/sliver.go](https://github.com/BishopFox/sliver/blob/v1.7.3/client/command/sliver.go).
- Console command-name constants include operators/new-operator/kick-operator/multiplayer, sessions/background/use/taskmany/reconfig/prune/tasks/cancel, generate/regenerate/profiles/beacon/beacons, traffic-encoders, c2profiles, certificates, loot/creds, implants/canaries, jobs/mtls/wg/dns/http/https/named-pipe/tcp, msf/msf-inject, ps/ping/kill/terminate/services, shell/execute/children, ls/mv/cp/rm/mkdir/cd/pwd/cat/edit/hex-edit/download/head/tail/grep/upload, ifconfig/netstat/chmod/chown/chtimes/mount/memfiles, procdump/impersonate/runas/getsystem/rev2self/execute-assembly/execute-shellcode/migrate/sideload/spawndll, extensions/armory/aliases/stage-listener, screenshot/psexec/backdoor/make-token/env/registry/pivots/wg-config/wg-socks/wg-portfwd/monitor/mcp/ssh/dllhijack/interactive/close/wasm, portfwd/socks5/rportfwd, reaction, hosts/ioc, getprivs, shikata-ga-nai/shellcode-encoders, cursed/{chrome,console,electron,edge,cookies}, builders, crack/{stations,wordlists,rules,hcstat2} — [client/constants/constants.go](https://github.com/BishopFox/sliver/blob/v1.7.3/client/constants/constants.go).
- Offline `sliver-client implant --help` on this host (v1.7.9) lists implant groups Core/Info/Filesystem/Network/Execution/Privileges/Process and extra commands **`ai`** and **`opfor`** not present in the v1.7.3 bind list; also `interactive`, `wasm`, `cursed`, `rportfwd`, `memfiles`, `mount`, `grep`, `head`, `tail`, `hex-edit`, `chtimes` — local binary `/usr/local/bin/sliver-client` (`sliver-client version` → v1.7.9).
- Top-level `sliver-client` commands: `console`, `implant`, `import`, `mcp`, `version`, `completion` — `sliver-client --help`; MCP is documented as experimental stdio/HTTP-SSE — [MCP.md](https://github.com/BishopFox/sliver/blob/v1.7.3/docs/sliver-docs/pages/docs/md/MCP.md); [sliver.sh MCP](https://sliver.sh/docs?name=MCP).
- Generate CLI flags (session/beacon): os/arch/name/debug/debug-file/evasion/skip-symbols/shellcode-encoder/exports/canary, mtls/wg/http/dns/named-pipe/tcp-pivot, wg key-exchange/tcp-comms, run-at-load/netgo/traffic-encoders/strategy/reconnect/poll-timeout/max-errors/c2profile, limit-datetime/domainjoined/username/hostname/fileexists/locale, spoof-metadata, format, full Donut `--shellcode-*` set; beacon-only days/hours/minutes/seconds/jitter; compile-time template/external-builder/save — [client/command/generate/commands.go](https://github.com/BishopFox/sliver/blob/v1.7.3/client/command/generate/commands.go) (`coreImplantFlags`, `coreBeaconFlags`, `compileImplantFlags`).
- `ImplantConfig` protobuf fields include IsBeacon, BeaconInterval/Jitter, Debug/Evasion/ObfuscateSymbols, TemplateName, SGNEnabled, IncludeMTLS/HTTP/WG/DNS/NamePipe/TCP, WG ports, ReconnectInterval/MaxConnectionErrors/PollTimeout, C2, CanaryDomains, ConnectionStrategy, Limit*, Format/IsSharedLib/IsService/IsShellcode/RunAtLoad/exports/ShellcodeConfig/ShellcodeEncoder, HTTPC2ConfigName, NetGoEnabled, TrafficEncodersEnabled/TrafficEncoders — [client.proto ImplantConfig](https://github.com/BishopFox/sliver/blob/v1.7.3/protobuf/clientpb/client.proto).
- BOF/COFF execution is **not** a first-class RPC; it is an **armory extension** (COFFLoader) installed per client, then `CallExtension` — [BOF and COFF Support](https://sliver.sh/docs?name=BOF+and+COFF+Support); local [BOF and COFF Support.md](file:///home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/docs/sliver-docs/pages/docs/md/BOF%20and%20COFF%20Support.md).
- Traffic encoders are WASM encode/decode callbacks, v1.6.0+, RPCs TrafficEncoderMap/Add/Rm — [Traffic Encoders wiki](https://github.com/BishopFox/sliver/wiki/Traffic-Encoders/81c13a10ea12429d30f73bb804dcc2c6761503f6); [Traffic Encoders docs](https://sliver.sh/docs?name=Traffic+Encoders).
- Watchtower (`monitor start/stop`) polls VT/X-Force for implant hashes; extra RPCs MonitorListConfig/AddConfig/DelConfig exist in proto — [Watchtower.md](https://github.com/BishopFox/sliver/blob/v1.7.3/docs/sliver-docs/pages/docs/md/Watchtower.md).
- External builders are separate `sliver-server builder` processes; RPCs Builders/BuilderRegister/BuilderTrigger/GenerateExternal* — [External Builders](https://sliver.sh/docs?name=External+Builders).
- `ReconfigureReq` has ReconnectInterval, BeaconInterval, BeaconJitter, C2URI — [sliver.proto](https://github.com/BishopFox/sliver/blob/v1.7.3/protobuf/sliverpb/sliver.proto).

### Inferences
- The “catalog” operators actually use is **RPC ∪ client-only features**. Armory, reactions, cursed (chromedp), MCP, settings/themes, and (in 1.7.9) OPFOR CNA / AI TUI live in the client binary; they are not all gRPC methods.
- Comparing this UI to “native Sliver” must use **v1.7.3 protobuf** for what the Go client *can* call, and **v1.7.9/master** for what a current operator console already has.

### Gaps
- Did not attach `sliver-client console` to a live sliver-server, so server-menu `--help` text was taken from source bind lists rather than a live `help` dump.
- Exact unique RPC count on master after wrapping lines was not re-counted beyond the extra AI/crack-job blocks listed above.
- OPFOR CNA (`#2352`, v1.7.7) command/RPC mapping was not fully unpacked beyond the implant-help name `opfor` and the release note.

## For each major command family, is it in this UI’s backend and frontend?

### Takeaway
The UI already wraps a **wide operator core** (sessions, beacons list/tasks, listeners, generate, jobs, loot, hosts, websites, canaries, HTTP C2 profiles, socks, portfwd, pivots, WG, aliases, stage TCP, shellcode RDI/encoders) via `/api/*` in [backend/internal/api/server.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/server.go) and pages under [frontend/src/pages](file:///home/cup/Documents/personal/sliv/frontend/src/pages). Large native families are **missing or partial**: beacon *tasking*, generate-beacon, armory/BOF package manager, wasm, crackstation, creds-as-creds (vs loot), rportfwd, cursed, reactions, MCP/AI, remote builders, certificates, traffic-encoder add/rm, filesystem extras (grep/cp/memfiles/mount/chmod), and most execute-assembly/execute flags. `/api/builders` is a **name collision**: it lists **implant builds**, not RPC `Builders()`.

### Cited Findings

**How the UI is wired**
- HTTP contract is a single `apiRoutes()` list (auth, connect, sessions/fs/ops, beacons, generate, listeners, loot, hosts, websites, http-c2, traffic-encoders list, WG, socks, jobs, events, builders=implant builds, stage, shellcode, loaders, aliases, monitor start/stop, prune, …) plus `/ws/sessions/{id}/terminal` — [backend/internal/api/server.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/server.go) `apiRoutes()`.
- Frontend `api` object in [frontend/src/lib/api.ts](file:///home/cup/Documents/personal/sliv/frontend/src/lib/api.ts) calls those paths; nav in [frontend/src/lib/nav.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/lib/nav.tsx); routes in [frontend/src/App.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/App.tsx).
- Backend wrappers live in [backend/internal/sliver/*.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver); they almost always set `commonpb.Request{SessionID: …}` and never `BeaconID` except `OpenSessionFromBeacon` / beacon rename/rm/tasks — [beacon_ops.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/beacon_ops.go), [ops.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/ops.go), [ops_extended.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/ops_extended.go).

**Coverage by family (v1.7.3 RPC / CLI → UI)**

| Family | Native RPC / CLI | Backend | Frontend | Status |
|---|---|---|---|---|
| Connect / version / operators | GetVersion, GetOperators; client configs `~/.sliver-client/configs` | Version, connect/disconnect, list/use profiles, GetOperators | Settings connect/profile; **operators API unused in pages** | **partial** |
| Sessions list/kill/rename/close/prune | GetSessions, Kill, Rename, CloseSession; `sessions prune` | Sessions, KillSession, RenameSession, CloseSession, PruneSessions | SessionsPage, SessionDetailPage | **implemented** (kill always `Force: true`) |
| Beacons list/rm/rename/tasks | GetBeacons, GetBeacon, RmBeacon, GetBeaconTasks, GetBeaconTaskContent | yes | BeaconsPage, BeaconDetailPage, TasksPage, BeaconTasksModal | **partial** (see Q5; no CancelBeaconTask) |
| Beacon → session | OpenSession (`interactive`) | OpenSessionFromBeacon (empty C2S, Delay 0) | Beacon detail “open session” | **partial** |
| Reconfigure | Reconfigure (reconnect + beacon interval/jitter + C2URI) | ReconfigureSession: **ReconnectInterval + SessionID only** | AdvancedTab reconnect seconds | **partial** |
| Monitor / watchtower | MonitorStart/Stop/ListConfig/Add/Del | MonitorStart/Stop only | BeaconsPage toggle | **partial** |
| Listeners / jobs | StartMTLS/HTTP/HTTPS/DNS/WG, GetJobs, KillJob, RestartJobs | StartListener (mtls/http/https/dns/wg), Jobs, StopJob; **no RestartJobs** | ListenersPage (domain/website/ACME/OTP/long-poll), JobsPage | **partial** (WG extra ports, DNS canary/no-txt, certs not exposed) |
| Stage listeners | StartTCPStagerListener; `profiles stage` / GenerateStage / StageImplantBuild; `stage-listener` TCP-only in 1.7.3 | GenerateStage + StartTCPStageListener + list/stop via jobs filter | LoadersPage tab `stage` | **partial** (TCP + AES/RC4/compress; no StageImplantBuild HTTP resource-id path; MSF stager stub dead) |
| Generate / profiles / builds | Generate, Regenerate, ImplantBuilds, ImplantProfiles, Save/Delete profile/build, GetCompiler | GenerateImplant, Regenerate, ImplantBuilds, profiles CRUD, CompilerInfo | ImplantsPage | **partial** (see generate flags below) |
| Generate beacon | `generate beacon` + coreBeaconFlags | `GenerateRequest.IsBeacon` exists | ImplantsPage **never sets `is_beacon`**; saveProfile hardcodes `is_beacon: false` | **missing in UI** (API could, form does not) |
| HTTP C2 profiles | GetHTTPC2Profiles/ByName, SaveHTTPC2Profile; CLI import/export | List/Get/Save | HttpC2Page JSON editor + **UI templates** `ms-update` / `jquery-cdn` | **partial** (no CLI-style import/export files; templates are extra) |
| Traffic encoders | TrafficEncoderMap/Add/Rm; generate `--traffic-encoders` | ListTrafficEncoders only | ImplantsPage enable/select; HttpC2Page does not add/rm WASM | **partial** |
| Shellcode encode / RDI | ShellcodeEncoder, ShellcodeEncoderMap, ShellcodeRDI | EncodeShellcode, ListShellcodeEncoders, ShellcodeRDI | LoadersPage + AdvancedTab RDI | **partial** (native client also post-encodes after Generate; UI generate does not call ShellcodeEncoder after RPC Generate) |
| Canaries | Canaries; generate `--canary` | Canaries() list | CanariesPage list/filter burned | **partial** (no generate-time canary domains) |
| Loot | LootAdd/Rm/Update/Content/All | LootAll/Add/Rename/Content/Remove | LootPage files + credential add | **implemented** (loot path) |
| Credentials store | Creds/CredsAdd/Rm/Update, GetCredByID, GetCredsByHashType, GetPlaintextCredsByHashType, CredsSniffHashType | Creds() only as loot-credential helper (`findCred` / CredsAdd) | LootPage credential type; **nav icon `credentials` unused**, no Creds page | **partial** |
| Hosts / IOC | Hosts, Host, HostRm, HostIOCRm | yes | HostsPage | **implemented** |
| Websites | Websites, Website, Add/Update/Remove content, WebsiteRemove | yes | WebsitesPage | **implemented** |
| WireGuard C2 | GenerateWGClientConfig, GenerateUniqueIP, WG* forward/socks, StartWGListener | yes | WgTab on session; listener type `wireguard` | **partial** (no wg key-exchange/tcp-comms generate knobs) |
| Socks5 | CreateSocks/CloseSocks/SocksProxy | Socks manager + stream | SocksPage | **implemented** (session tunnels) |
| Portfwd | Portfwd | PortForwardManager | PortfwdTab | **implemented** (forward only) |
| Reverse portfwd | StartRportFwdListener, GetRportFwdListeners, StopRportFwdListener; CLI `rportfwd` | **none** | **none** | **missing** |
| Pivots | PivotStart/Stop/SessionListeners, PivotGraph; types TCP/UDP/NamedPipe | yes | PivotTab | **implemented** (listener types TCP/UDP/NamedPipe) |
| Filesystem | Ls/Cd/Pwd/Mv/Cp/Rm/Mkdir/Download/Upload/Grep/Chmod/Chown/Chtimes/Memfiles*/Mount; CLI cat/head/tail/edit/hex-edit | Ls/Pwd/Cd/Download/Upload/Mkdir/Rm/Mv only | FilesTab / FilesPage | **partial** |
| Process | Ps, Terminate, ProcessDump; CLI services list/info | Ps, KillProcess, ProcessDump | ProcessesTab (kill/migrate/dump) | **partial** (no services *list*) |
| Network info | Ifconfig, Netstat | yes | NetworkTab / NetworkPage | **implemented** |
| Env | GetEnv/SetEnv/UnsetEnv | yes | EnvTab | **implemented** |
| Execute | Execute, ExecuteWindows, ExecuteChildren; flags token/hidden/ppid/background/loot/env | Execute(path, args, Output=true) only | ExecTab | **partial** |
| Shell | Shell, ShellResize, TunnelData | terminal.go WebSocket binary frames | TerminalPage xterm.js | **implemented** (one shell per session; no `shell ls/attach/kill` multi-shell) |
| Screenshot | Screenshot | yes | ScreenshotTab | **implemented** |
| Registry | RegistryRead/Write/CreateKey/DeleteKey/ListSubKeys/ListValues/ReadHive | all except ReadHive | RegistryTab browse/read/write/delete; **regCreateKey in api.ts unused** | **partial** |
| Privileges / tokens | Impersonate, MakeToken, RevToSelf, GetSystem, GetPrivs, CurrentTokenOwner, RunAs, ExecuteWindows (token) | Impersonate/MakeToken/RevToSelf/GetSystem/GetPrivs/CurrentTokenOwner/RunAs/ExecuteToken | TokensTab | **partial** (execute-token is Execute with Output; not full ExecuteWindows flags) |
| execute-assembly | ExecuteAssembly (+ in-process, AMSI/ETW, method/class, ppid, runtime) | Assembly/arguments/process only | AdvancedTab mode `assembly` | **partial** / **buried** |
| sideload / spawndll | Sideload, SpawnDll | data/process/args/entryPoint | AdvancedTab | **partial** / **buried** |
| migrate | Migrate (+ encoder) | pid only | ProcessesTab migrate | **partial** |
| execute-shellcode | Task RPC; CLI rwx/pid/process/interactive/SGN | Task(data, pid, rwx) | AdvancedTab | **partial** / **buried** |
| psexec | client helper over generate+service | PsExec | AdvancedTab | **partial** / **buried** (default service name/desc still “Sliver”) |
| msf / msf-inject | Msf, MsfRemote | yes | AdvancedTab | **partial** / **buried** |
| MSF stager | historically MsfStage; **removed from sliver-server** | MsfStage always errors | AdvancedTab still calls `/api/msf/stage` | **missing** (dead stub) — [msf.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/msf.go) |
| backdoor / dllhijack | Backdoor, HijackDLL | yes | AdvancedTab | **partial** / **buried** |
| Services | Services, ServiceDetail, StartServiceByName, StartService, StopService, RemoveService | Start/Stop/Remove only | ServicesTab forms (no list) | **partial** / **buried** (tab also hosts SSH + extensions) |
| SSH | RunSSHCommand | yes | ServicesTab | **partial** / **buried** |
| Extensions (in-implant) | RegisterExtension, CallExtension, ListExtensions | yes | ServicesTab | **partial** / **buried** |
| Aliases | client-local alias packages; CLI aliases load/install/rm | local tar.gz install + RunAlias → ExecuteAssembly/Sideload | AliasesPage | **partial** (no armory fetch) |
| Armory | client HTTP to armory; install aliases/extensions/BOFs | **none** | copy says “e.g. from the Sliver armory” only | **missing** |
| Wasm extensions | RegisterWasmExtension, ListWasmExtensions, ExecWasmExtension; CLI `wasm` | **none** | **none** | **missing** |
| Cursed | client chromedp toolkit (chrome/edge/electron/cookies) | **none** | **none** | **missing** |
| Crackstation | Crack, Crackstation*, CrackFile*, CrackTask* (1.7.3); CrackJobs* on master | **none** | **none** | **missing** |
| Reactions | client-local `reaction set/unset/save/reload` | **none** | **none** | **missing** |
| Certificates | GetCertificateInfo, GetCertificateAuthorityInfo | **none** | **none** | **missing** |
| External builders | Builders, BuilderRegister, BuilderTrigger, GenerateExternal* | **none**; `/api/builders` → ImplantBuilds | ImplantsPage “builders” = stored builds | **missing** (RPC) / **misnamed** (HTTP) |
| Spoof metadata | GenerateSpoofMetadata; `--spoof-metadata` | **none** | **none** | **missing** |
| Multiplayer admin | new-operator / kick-operator (typically server CLI); GetOperators | GetOperators | unused | **missing** UI |
| MCP | `sliver-client mcp` / console `mcp` | **none** | **none** | **missing** |
| AI | master AI RPCs; v1.7.9 `implant ai` | **none** (not in v1.7.3 stub) | **none** | **missing** |
| OPFOR CNA | v1.7.7+ `opfor` | **none** | **none** | **missing** |
| taskmany / aka | CLI taskmany, aka | **none** | **none** | **missing** |
| Events | Events stream | Events() 10s poll of live stream; **does not copy `e.Beacon`** despite EventView field | EventsPage | **partial** |
| Client log | ClientLog stream | **none** | **none** | **missing** (low priority) |
| Ping | Ping | yes | SessionDetail ping | **implemented** |
| Info whoami/getuid/getpid | CLI info/* | SessionView has Username/UID/GID/PID | session sidebar | **partial** (display only) |

**Generate flag subset actually sent**
- UI `GenerateRequest` maps name/os/arch/format/c2/interval/jitter/maxErrors/is_beacon/debug/evasion/obfuscate, http_c2_profile, traffic_encoders*, limits (domainjoined/hostname/username/datetime/file_exists/locale), connection_strategy, sgn_enabled, shellcode_entropy, shellcode_encoder, replace_existing — [implants.go GenerateRequest](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/implants.go).
- ImplantsPage form actually collects: name, os, arch, format, **single** C2 URL, interval, jitter, obfuscate, debug, evasion, sgn (shellcode→SHIKATA_GA_NAI only), shellcode entropy, replace existing, HTTP C2 profile, traffic encoder enable/select, limit domainjoined/hostname/username — [ImplantsPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/ImplantsPage.tsx) `buildConfig()`.
- Not in the generate form: is_beacon, named-pipe/tcp-pivot C2, canary domains, netgo, run-at-load, exports, poll-timeout, reconnect vs beacon split, limit datetime/file/locale (backend fields exist, form omits), Donut compress/bypass/exitopt/headers/thread/unicode/oep, template, external-builder, spoof-metadata, XOR/XOR_DYNAMIC encoder choice (only SGN toggle).

**MSF stager vs native stage**
- `MsfStage` explicitly returns `"MSF stager generation is not supported; use /api/stage/generate or /api/stage-listeners"` — [msf.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/msf.go).
- Loaders stage path wraps GenerateStage + TCP StartTCPStagerListener with AES/RC4/compress — [stage.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/stage.go); [LoadersPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/LoadersPage.tsx).
- Native HTTP staging in 1.7 is `profiles stage` / `StageImplantBuild` + HTTP C2 `stagerHandler`, while `stage-listener` is TCP-only — prior notes [sliver_native_capabilities.md](file:///home/cup/Documents/personal/sliv/research_notes/Sliver%20encrypt%20at%20rest%20loaders/sliver_native_capabilities.md); [BishopFox/sliver#2009](https://github.com/BishopFox/sliver/issues/2009).

### Inferences
- Product-wise the UI is a **session-centric operator workstation** with a strong generate/listeners/HTTP-C2/loaders spine, not a 1:1 sliver-client clone.
- “Buried” is real: AdvancedTab and ServicesTab pack msf, psexec, RDI, backdoor, dllhijack, SSH, and extension call — first-class for files/ps/screenshot, second-class for post-ex.
- `/api/builders` will confuse anyone looking for RPC `Builders()` (external compile nodes).

### Gaps
- Did not runtime-exercise each handler against a live sliver-server; coverage is from source (routes + wrappers + pages).
- Whether `Generate` server-side honors `ImplantConfig.ShellcodeEncoder` without client post-process was not re-verified in v1.7.3 server code here (prior notes said client-side); UI does not call `ShellcodeEncoder` after `Generate`.
- AliasDir is relative `"aliases"` in the UI process — [aliases.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/aliases.go) — not confirmed to share `~/.sliver-client` alias storage with stock sliver-client.

## What did Sliver add recently (1.6 / 1.7: HTTP C2 profiles, traffic encoders, Wasm, multiplayer, builders, crackstation) that the UI still misses?

### Takeaway
Of the headline 1.6–1.7 platform features, this UI **has** HTTP C2 profile CRUD, traffic-encoder *selection at generate*, compiler-info, TCP stage, and shellcode encoder/RDI APIs. It **still misses** traffic-encoder WASM add/rm, Wasm implant extensions, crackstation, remote builders, generate-beacon as a first-class flow, MCP, AI, OPFOR CNA, rportfwd lifecycle work from 1.7.7, and most Donut/spoof-metadata generate knobs. It is also **one minor version behind** the sliver-client on this machine (UI 1.7.3 vs client 1.7.9), so it cannot see master AI/crack-job RPCs without a module bump.

### Cited Findings
- **HTTP C2 profiles (1.5 file → 1.6 RPC):** v1.6.0 PR “V1.6.0/http c2” (#1454), profile updates (#1456), export (#1623) — [v1.6.0 release](https://github.com/BishopFox/sliver/releases/tag/v1.6.0). UI implements Get/Save via [httpc2.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/httpc2.go) and [HttpC2Page.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/HttpC2Page.tsx). **Missing:** dedicated import/export commands; default-profile generation wizard like `c2profiles generate`.
- **Traffic encoders (v1.6.0):** WASM encode/decode — [wiki](https://github.com/BishopFox/sliver/wiki/Traffic-Encoders/81c13a10ea12429d30f73bb804dcc2c6761503f6). UI lists Map and can set `TrafficEncodersEnabled` + names on generate — [encoders.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/encoders.go), ImplantsPage. **Missing:** `TrafficEncoderAdd` / `TrafficEncoderRm` (CLI `generate traffic-encoders add|rm`).
- **Wasm extensions:** RPCs Register/List/ExecWasmExtension; implant command `wasm` — [sliver.go](https://github.com/BishopFox/sliver/blob/v1.7.3/client/command/sliver.go); v1.6.0 “Add wasm output in beacon mode” (#1283). **UI: missing.**
- **Memfiles / grep / cp / head / tail / mount / services / registry hive** landed across 1.6.x (#1238, #1346, #1422, #1407, #1596, #1557, #1559) — [v1.6.0 notes](https://github.com/BishopFox/sliver/releases/tag/v1.6.0). UI filesystem/process/registry tabs do not wrap those RPCs (except services start/stop/remove).
- **taskmany** (#1311, v1.6): **missing.**
- **Multi-builder 1:n** (#1549) and External Builders docs — [External Builders](https://sliver.sh/docs?name=External+Builders). UI `/api/builders` is ImplantBuilds — [server.go handleBuilders](file:///home/cup/Documents/personal/sliv/backend/internal/api/server.go). **RPC Builders/GenerateExternal: missing.**
- **Crackstation:** full Crack* RPC family in v1.7.3 proto; master adds CrackJobs/Cancel/Pause/Resume/Top. **UI: missing.**
- **MCP (1.6.4+ docs):** `sliver-client mcp` — [MCP.md](https://github.com/BishopFox/sliver/blob/v1.7.3/docs/sliver-docs/pages/docs/md/MCP.md). **UI: missing.**
- **v1.7.0:** C2/mux (#2161), Darwin/arm64 shellcode (#2162), exec background (#2163), gRPC API updates (#2165) — [v1.7.0](https://github.com/BishopFox/sliver/releases/tag/v1.7.0). UI execute has no `--background` / ExecuteChildren.
- **v1.7.7:** OPFOR CNA BOF scripting (#2352), windows/shell handling (#2353), reverse portfwd lifecycle (#2356), portfwd/SOCKS5 hardening (#2359) — [v1.7.7](https://newreleases.io/project/github/BishopFox/sliver/release/v1.7.7). UI has no opfor; no rportfwd; portfwd/socks exist but not the 1.7.7 lifecycle work as explicit UI.
- **v1.7.9 client on this host** adds implant `ai` (master AI RPCs) — `sliver-client implant --help`; [master services.proto AI block](https://github.com/BishopFox/sliver/blob/master/protobuf/rpcpb/services.proto). **UI module is 1.7.3: cannot call AI RPCs.**
- **CVE-2026-77622** PNG decoder DoS fixed in **1.7.6**; UI talking to older servers remains exposed on the *server* side — [OpenCVE CVE-2026-77622](https://app.opencve.io/cve/CVE-2026-77622). Not a UI feature gap, but a version-compat note.
- HTTP C2 customization itself dates to v1.5 `http-c2.json`; 1.6 moved it onto RPC/profiles — [HTTP(S) C2 wiki](https://github.com/BishopFox/sliver/wiki/HTTP(S)-C2/0ccecf82b9be940812f7a03ee2b6666bc16c7467).

### Inferences
- The UI invested in **network OPSEC** (HTTP C2 page, encoder *toggle*, camouflage generate fields) and **payload packaging extras** (Loaders), which matches 1.6’s HTTP-C2/traffic-encoder story — but stopped short of the **package-manager / crack / wasm / builder-farm** half of 1.6–1.7.
- Staying on protobuf **v1.7.3** is itself a coverage freeze: 1.7.7 rportfwd, 1.7.9 AI, and master crack-job RPCs are unreachable until `go.mod` moves.

### Gaps
- Did not diff every v1.6.1–v1.7.9 patch RPC-by-RPC; table focuses on operator-visible families named in the assignment.
- Whether 1.7.9 server proto equals master AI/crack-job set was inferred from client help + master proto, not from a 1.7.9 module tree (this machine only vendors v1.7.3).

## Which session-interactive commands have first-class UI vs buried vs missing?

### Takeaway
First-class session UX is **files, processes (ps/kill/migrate/dump), network, env, basic execute, screenshot, portfwd, registry browse, tokens, WG, pivots, and xterm shell**. Post-ex workhorses **execute-assembly / sideload / spawndll / execute-shellcode / msf / psexec / backdoor / dllhijack** are **buried in AdvancedTab** with thin flags. **Wasm, cursed, rportfwd, grep/cp/chmod/memfiles/mount, in-process assembly+AMSI/ETW, services inventory, registry hive** are **missing**. Nothing here is an AV bypass; AdvancedTab even still defaults psexec to service name `"Sliver"`.

### Cited Findings

**First-class (own session tab or page)**
- Session tabs: files, processes, network, env, exec, screenshot, portfwd, registry, advanced, tokens, wg, pivot, services — [SessionDetailPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/SessionDetailPage.tsx) `TABS`.
- Shell: `/sessions/:id/terminal` WebSocket `[msgType][4-byte BE len][payload]` types 0x01 data / 0x02 resize / 0x03 close — [terminal.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/terminal.go), [terminal.ts](file:///home/cup/Documents/personal/sliv/frontend/src/lib/terminal.ts); native RPCs Shell/ShellResize/TunnelData — [services.proto](https://github.com/BishopFox/sliver/blob/v1.7.3/protobuf/rpcpb/services.proto).
- FilesTab: list/cd/pwd/cat/download/upload/mkdir/rm/mv — [FilesTab.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/components/session/FilesTab.tsx); backend [files.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/files.go).
- ProcessesTab: ps, terminate, migrate(pid), procdump download — [ProcessesTab.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/components/session/ProcessesTab.tsx).
- ExecTab: path + whitespace-split args, Output=true, no Windows flags — [ExecTab.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/components/session/ExecTab.tsx); [ops.go Execute](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/ops.go).
- TokensTab: impersonate, make-token, getsystem (default host `spoolsv.exe`), rev2self, token owner, getprivs, runas, execute-token — [TokensTab.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/components/session/TokensTab.tsx).
- PivotTab: TCP/UDP/NamedPipe listeners + graph — [PivotTab.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/components/session/PivotTab.tsx).
- PortfwdTab: bind addr/port → remote host/port — [PortfwdTab.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/components/session/PortfwdTab.tsx).
- ScreenshotTab, EnvTab, NetworkTab, WgTab, RegistryTab as dedicated tabs.

**Buried (AdvancedTab / ServicesTab)**
- AdvancedTab modes assembly/sideload/spawndll; reconfigure reconnect; msf/msfRemote; msf stage (dead); backdoor; dllhijack; RDI convert; execute-shellcode (pid/rwx); psexec with defaults `ServiceName=Sliver`, `ServiceDesc=Sliver implant`, `BinPath=C:\Windows\Temp` — [AdvancedTab.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/components/session/AdvancedTab.tsx).
- Native execute-assembly flags in-process/AMSI/ETW/method/class/app-domain/arch/ppid/runtime — [exec/commands.go](https://github.com/BishopFox/sliver/blob/v1.7.3/client/command/exec/commands.go); UI ExecuteAssembly sets only Assembly/Arguments/Process — [ops_extended.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/ops_extended.go).
- Native execute flags `--token/--hidden/--ppid/--background/--loot/--env/--stdout/--stderr` — [exec/commands.go](https://github.com/BishopFox/sliver/blob/v1.7.3/client/command/exec/commands.go); UI omits them.
- execute-shellcode uses RPC `Task`, not the CLI’s interactive/SGN path — [psexec.go ExecuteShellcode](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/psexec.go).
- ServicesTab: start/stop/remove service forms + SSH + extension register/list/call — [ServicesTab.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/components/session/ServicesTab.tsx). No `Services` / `ServiceDetail` list RPC.

**Missing vs implant `--help` (v1.7.9)**
- Core: `ai`, `opfor`, `aka`, `background` (console concept), `tasks cancel`, full `reconfig` (beacon interval/jitter/C2).
- Filesystem: `cp`, `grep`, `head`, `tail`, `edit`, `hex-edit`, `memfiles`, `mount`, `chmod`/`chown`/`chtimes` (privilege group in CLI).
- Network: `rportfwd`.
- Execution: `cursed`, `wasm`; execute-assembly in-process; execute children; msf stager.
- Process: `services` inventory (`Services` RPC).
- Registry: `registry hive`.
- 3rd party: armory-installed BOF commands never appear as nav items (only raw CallExtension).

**Stock CLI OPSEC notes that the UI does not surface**
- Sliver docs/community treat interactive `shell` as poor OPSEC; UI still offers a prominent Terminal page — [README](file:///home/cup/Documents/personal/sliv/README.md) screenshots “full-screen xterm.js shell”.
- AdvancedTab psexec defaults match the names Microsoft hunting blogs associate with Sliver services — local [SLIVER_UI_AV_OPSEC_RESEARCH.md](file:///home/cup/Documents/personal/sliv/docs/SLIVER_UI_AV_OPSEC_RESEARCH.md) (research lead; not re-claimed as detection proof here).

### Inferences
- An operator can run a **full interactive session** from the UI for FS/ps/net/screenshot/shell/tokens/pivots/WG.
- An operator **cannot** match sliver-client for BOF/wasm/cursed/rportfwd/in-process .NET without dropping back to the console (or a raw extension call in ServicesTab).
- “First-class vs buried” is a UX gap even when the RPC is wrapped: msf/psexec/RDI are easy to miss.

### Gaps
- Did not click-test every AdvancedTab control against a Windows session.
- `execute-token` vs native `execute --token` / ExecuteWindows field parity was not byte-compared beyond the Go call in [privileges.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/privileges.go).
- Whether ServicesTab extension call can run a COFFLoader BOF with correctly typed args (armory manifest) was not verified.

## Beacon-specific UX (tasking, results, jitter, next-checkin) vs session UX

### Takeaway
Beacon **inventory** in this UI is good: list + detail show last/next checkin, interval/jitter, task table, result decode, rename/rm/prune, watchtower start/stop, and “open interactive session”. Beacon **tasking is essentially absent**: implant RPCs are session-ID-only, generate/profile save is session-only (`is_beacon: false`), reconfigure cannot set BeaconInterval/Jitter, and CancelBeaconTask is not wrapped. Native sliver-client uses the *same* implant menu on a beacon (async `Request.BeaconID`); this UI forces “open session” first.

### Cited Findings
- `BeaconView` includes LastCheckin, NextCheckin, Interval, Jitter — [data.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/data.go). BeaconsPage table renders next checkin and `Interval s / Jitter %` — [BeaconsPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/BeaconsPage.tsx).
- BeaconDetailPage: task DataTable (state/description/created/completed), base64 result decode, properties sidebar, OpenSession, remove — [BeaconDetailPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/BeaconDetailPage.tsx).
- TasksPage aggregates tasks across all beacons — [TasksPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/TasksPage.tsx).
- Wrapped beacon RPCs: GetBeacons/GetBeacon/RmBeacon/GetBeaconTasks/GetBeaconTaskContent, Rename (BeaconID), OpenSession, MonitorStart/Stop, PruneBeacons — [beacon_ops.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/beacon_ops.go), [prune.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/prune.go).
- **Not wrapped:** CancelBeaconTask, UpdateBeaconIntegrityInformation — [services.proto](https://github.com/BishopFox/sliver/blob/v1.7.3/protobuf/rpcpb/services.proto).
- OpenSessionFromBeacon sends `C2S: []string{}`, `Delay: 0` — [beacon_ops.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/beacon_ops.go). Native `interactive` can pass C2s/delay — [sessions/commands.go InteractiveStr](https://github.com/BishopFox/sliver/blob/v1.7.3/client/command/sessions/commands.go).
- ReconfigureSession sets only `ReconnectInterval` + `SessionID` — [beacon_ops.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/beacon_ops.go). Proto also has BeaconInterval, BeaconJitter, C2URI — [sliver.proto ReconfigureReq](https://github.com/BishopFox/sliver/blob/v1.7.3/protobuf/sliverpb/sliver.proto).
- Execute/Ls/… wrappers use `Request{SessionID: sessionID}` only, e.g. [ops.go Execute](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/ops.go), [files.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/files.go), [ops_extended.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/ops_extended.go). Native implant commands work on beacons via BeaconID + async response — implant menu bind in [sliver.go](https://github.com/BishopFox/sliver/blob/v1.7.3/client/command/sliver.go); `tasks` / `tasks fetch` / `tasks cancel` — [tasks/commands.go](https://github.com/BishopFox/sliver/blob/v1.7.3/client/command/tasks/commands.go).
- ImplantsPage `saveImplantProfile({ … is_beacon: false …})` and `buildConfig()` omit `is_beacon` — [ImplantsPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/ImplantsPage.tsx). Native `generate beacon` has days/hours/minutes/seconds/jitter flags — [generate/commands.go coreBeaconFlags](https://github.com/BishopFox/sliver/blob/v1.7.3/client/command/generate/commands.go).
- Host pages (Files/Processes/Network) use SessionPicker over **sessions**, not beacons — [FilesPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/FilesPage.tsx).
- Events mapper copies Session and Job but **not** Beacon onto EventView — [data.go eventToView](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/data.go). Native events include `beacon-registered` and `beacon-taskresult` — [constants.go](https://github.com/BishopFox/sliver/blob/v1.7.3/client/constants/constants.go).
- Terminal WebSocket is `/ws/sessions/{id}/terminal` only — [server.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/server.go). Native shell is session-only anyway (beacon must `interactive` first).

### Inferences
- The UI treats beacons as **callback objects to watch and promote**, not as **async tasking targets**. That is the largest functional gap versus stock sliver-client for long-haul implants.
- Even the generate form’s interval/jitter knobs are **session reconnect** semantics unless `IsBeacon` is set; saving a “profile” from the form cannot create a beacon profile.
- Task results UX (global Tasks page + per-beacon drawer) is ahead of stock console *listing*, but useless for issuing work.

### Gaps
- Did not confirm whether passing a beacon ID in `/api/sessions/{id}/exec` accidentally works if IDs collide; source always sets SessionID, so a beacon ID would be the wrong field.
- Beacon integrity (`UpdateBeaconIntegrityInformation`) purpose/UI mapping was not researched beyond the RPC name.
- `taskmany` multi-beacon fan-out (v1.6) has no UI analogue; not prototyped.

## UI-only extras (not in stock sliver-client)

### Takeaway
This fork adds a **browser/desktop operator shell**: login gate, i18n, dashboard, favorites, loaders (host-side Go stub + XOR + persistence templates), HTTP C2 starter templates, implant→loaders deep link, replace-existing generate, and WebView2 packaging. Those are product features, not Sliver RPCs. They do not replace armory/wasm/crack/beacon-tasking.

### Cited Findings
- Single static binary with embedded React UI; Windows WebView2 vs HTTP on other OS — [README.md](file:///home/cup/Documents/personal/sliv/README.md); [AGENTS.md](file:///home/cup/Documents/personal/sliv/AGENTS.md).
- Optional UI login `/api/auth/*` — [server.go](file:///home/cup/Documents/personal/sliv/backend/internal/api/server.go); [LoginPage](file:///home/cup/Documents/personal/sliv/frontend/src/pages/LoginPage.tsx).
- i18n en+zh required to match — [AGENTS.md](file:///home/cup/Documents/personal/sliv/AGENTS.md); locales [en.ts](file:///home/cup/Documents/personal/sliv/frontend/src/i18n/locales/en.ts) / [zh.ts](file:///home/cup/Documents/personal/sliv/frontend/src/i18n/locales/zh.ts).
- Grouped nav, favorites, dashboard — [nav.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/lib/nav.tsx), [DashboardPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/DashboardPage.tsx).
- **Loaders** (`POST /api/loaders/build`): compile-on-host Go stub, hide-console, XOR, persistence (HKCU Run / schtask / startup LNK / systemd user / cron / LaunchAgent) — [loader/options.go](file:///home/cup/Documents/personal/sliv/backend/internal/loader/options.go); [LoadersPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/LoadersPage.tsx); README OPSEC section. **Not** a Sliver RPC. Honest non-FUD framing is documented in [SLIVER_UI_AV_OPSEC_RESEARCH.md](file:///home/cup/Documents/personal/sliv/docs/SLIVER_UI_AV_OPSEC_RESEARCH.md).
- HTTP C2 **client-side templates** `ms-update` and `jquery-cdn` — [HttpC2Page.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/HttpC2Page.tsx).
- Generate `replace_existing` deletes prior ImplantBuilds then Generate — [implants.go](file:///home/cup/Documents/personal/sliv/backend/internal/sliver/implants.go).
- ImplantsPage “continue to Loaders” after shared/shellcode generate — [ImplantsPage.tsx](file:///home/cup/Documents/personal/sliv/frontend/src/pages/ImplantsPage.tsx).
- Host-centric pages wrapping SessionPicker (files/processes/network) — extra IA, not extra RPCs.
- xterm.js terminal vs stock console `shell` — extra presentation, same Shell RPC.

### Inferences
- Extras concentrate on **delivery workstation** (loaders/HTTP camouflage) and **GUI chrome** (auth, i18n, layout). They do not close the beacon-tasking or armory holes.
- Loaders persistence templates are **outside** Sliver generate; they are UI-host compiled stubs. Operators should not confuse them with implant `generate --format service`.

### Gaps
- Did not audit loader stub source for behavioral telemetry; out of scope for an RPC coverage map.
- Upstream 9Insomnie/sliver_ui vs this local tree delta was not git-diffed; notes describe **this workspace**.

## Source index

- Local UI: `/home/cup/Documents/personal/sliv/backend/internal/api/server.go`, `backend/internal/sliver/*.go`, `frontend/src/{App.tsx,lib/api.ts,lib/nav.tsx,pages/*,components/session/*}`
- Local Sliver module: `/home/cup/go/pkg/mod/github.com/bishopfox/sliver@v1.7.3/` (`protobuf/rpcpb/services.proto`, `client/command/{server,sliver,generate,exec}.go`, `client/constants/constants.go`, `docs/sliver-docs/pages/docs/md/*`)
- Installed client: `/usr/local/bin/sliver-client` v1.7.9
- GitHub: [BishopFox/sliver v1.7.3 services.proto](https://github.com/BishopFox/sliver/blob/v1.7.3/protobuf/rpcpb/services.proto), [master services.proto](https://github.com/BishopFox/sliver/blob/master/protobuf/rpcpb/services.proto), [v1.6.0](https://github.com/BishopFox/sliver/releases/tag/v1.6.0), [v1.7.0](https://github.com/BishopFox/sliver/releases/tag/v1.7.0), [v1.7.7](https://newreleases.io/project/github/BishopFox/sliver/release/v1.7.7)
- Docs: [sliver.sh](https://sliver.sh/docs), Traffic Encoders, External Builders, BOF/COFF, MCP, Watchtower, HTTP(S) C2
- Prior local leads (re-verified in source, not copied blindly): [sliver_native_capabilities.md](file:///home/cup/Documents/personal/sliv/research_notes/Sliver%20encrypt%20at%20rest%20loaders/sliver_native_capabilities.md), [SLIVER_UI_AV_OPSEC_RESEARCH.md](file:///home/cup/Documents/personal/sliv/docs/SLIVER_UI_AV_OPSEC_RESEARCH.md)
