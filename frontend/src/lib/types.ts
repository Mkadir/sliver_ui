export interface Session {
  ID: string
  Name: string
  UUID: string
  Hostname: string
  Username: string
  UID: string
  GID: string
  PID: number
  OS: string
  Arch: string
  Transport: string
  RemoteAddress: string
  LastCheckin: string
  ActiveC2: string
  Locale: string
  AgentVersion: string
  IsDead: boolean
  IsInteractive: boolean
}

export interface Beacon {
  ID: string
  Name: string
  UUID?: string
  Hostname: string
  Username: string
  OS: string
  Arch: string
  Transport: string
  RemoteAddress: string
  LastCheckin: string
  NextCheckin: string
  Interval: number
  Jitter: number
  ActiveC2: string
}

export interface Listener {
  ID: number
  Name: string
  JobID: number
  Protocol: string
  Addr: string
  TLS: boolean
}

export interface Event {
  Type: string
  Err: string
  Session?: Session
  Beacon?: Beacon
  Job?: Job
  Data: Record<string, unknown>
}

export interface ServerInfo {
  version: string
  connected: boolean
  error?: string
}

export interface OverviewCounts {
  sessions: number
  beacons: number
  jobs: number
  builders: number
  socks: number
}

export interface OverviewData {
  counts: OverviewCounts
}

export interface ImplantConfig {
  name: string
  os: string
  arch: string
  format: string
  target: string
  c2: { address: string; protocol: string }[]
  mtls: boolean
  http: boolean
  dns: boolean
  wireguard: boolean
  interval: number
  jitter: number
  maxConnectionErrors: number
  debug: boolean
  evasion: boolean
  obfuscate: boolean
  limitDomainJoined: boolean
  transport: string
  http_c2_profile?: string
  traffic_encoders_enabled?: boolean
  traffic_encoders?: string[]
  limit_hostname?: string
  limit_username?: string
  limit_datetime?: string
  limit_file_exists?: string
  limit_locale?: string
  connection_strategy?: string
  is_beacon?: boolean
  /** Polymorphic shellcode encoder at generate (shellcode format only). */
  sgn_enabled?: boolean
  /** Donut entropy: 1=none, 2=names, 3=names+encrypt (Windows shellcode). */
  shellcode_entropy?: number
  /** Donut AMSI/WLDP bypass: 1=none, 2=abort, 3=continue (signatured patch). */
  shellcode_bypass?: number
  /** Donut exit: 1=thread, 2=process, 3=block. */
  shellcode_exitopt?: number
  /** NONE | SHIKATA_GA_NAI | XOR | XOR_DYNAMIC */
  shellcode_encoder?: string
  /** Delete same-named build on the server before generate. */
  replace_existing?: boolean
  /** DNS canary FQDNs registered on generate. */
  canary_domains?: string[]
  /** CLI `generate --external-builder` — RPC GenerateExternal, not an ImplantConfig field. */
  external_builder_name?: string
  /** Unique name suffix, force obfuscate, branding clean of returned bytes. */
  polymorph?: boolean
}

export interface ShellcodeEncoderArch {
  arch: string
  encoders: Record<string, number>
  descriptions?: Record<string, string>
}

export interface ShellcodeEncodeResult {
  data_b64: string
  size: number
  encoder: string
  arch: string
}

export interface StageGenerateResult {
  filename: string
  data_b64: string
  size: number
  profile: string
  encrypted: boolean
  compress?: string
  aes_key?: string
  aes_iv?: string
  rc4_key?: string
  implant_name?: string
  prepend_size: boolean
}

export interface ForkRewriteResult {
  root: string
  module: string
  new_module?: string
  dry_run: boolean
  files: number
  hits: Record<string, number>
  changed: string[]
  skipped?: string[]
  next: string[]
  note: string
  needs_ui_build: boolean
}

export interface LoaderBuildResult {
  filename: string
  data_b64: string
  size: number
  os: string
  arch: string
  hide_console: boolean
  persistence: string
  rdi: boolean
  payload_size: number
  engine?: string
  dll_filename?: string
  dll_data_b64?: string
  clean?: {
    replaced?: string[]
    remaining?: string[]
    export?: string
    note?: string
  }
}

export interface StageListenerResult {
  job_id: number
  host: string
  port: number
  profile: string
  aes_key?: string
  aes_iv?: string
  rc4_key?: string
  payload_size: number
}

export interface StageListenerView {
  job_id: number
  name: string
  protocol: string
  port: number
  is_stage: boolean
}

export interface HTTPC2Fingerprint {
  looks_default: boolean
  reasons: string[]
}

export interface HTTPC2Profile {
  name: string
  created?: number
  server_config?: Record<string, unknown>
  implant_config?: Record<string, unknown>
  raw?: unknown
  looks_default?: boolean
  fingerprint?: HTTPC2Fingerprint
}

export interface ExternalBuilder {
  name: string
  operator_name: string
  goos: string
  goarch: string
  templates: string[]
  targets: string[]
}

export interface ArmoryPackage {
  name: string
  command_name: string
  repo_url: string
  public_key: string
  kind: 'alias' | 'extension' | string
}

export interface ArmoryIndex {
  source: string
  fetched_at: number
  packages: ArmoryPackage[]
}

export interface TrafficEncoder {
  name: string
  id: number
}

export interface TrafficEncoderTest {
  name: string
  completed: boolean
  success: boolean
  duration: number
  err?: string
}

export interface TrafficEncoderAddResult {
  name: string
  passed: boolean
  total_tests: number
  total_duration: number
  tests: TrafficEncoderTest[]
}

export interface ImplantBuild {
  Name: string
  ImplantConfig: ImplantConfigView
  ImplantBuildID: string
  Arch: string
  OS: string
}

export interface Job {
  ID: number
  Name: string
  Protocol: string
  Port: number
  Domains: string[]
  JobControl: string
}

export interface LootEntry {
  ID: string
  Name: string
  LootType: string
  FileType: string
  File: string
  Size: number
  DataB64?: string
  CredUser?: string
  CredPassword?: string
  CredAPIKey?: string
}

export interface LootReport {
  generated_at: string
  loot: {
    id: string
    name: string
    loot_type: string
    file_type?: string
    file?: string
    size?: number
    cred_user?: string
    has_cred?: boolean
  }[]
  canaries: Canary[]
  hosts: Host[]
  implants: { name: string; os: string; arch: string; sha256?: string }[]
}

export interface CompilerTarget {
  GOOS: string
  GOARCH: string
  Format: string
}

export interface CrossCompiler {
  TargetGOOS: string
  TargetGOARCH: string
  CCPath: string
  CXXPath: string
}

export interface CompilerInfo {
  GOOS: string
  GOARCH: string
  Targets: CompilerTarget[]
  CrossCompilers: CrossCompiler[]
}

export interface IOC {
  ID: string
  Path: string
  FileHash: string
}

export interface Host {
  Hostname: string
  HostUUID: string
  OSVersion: string
  IOCs: IOC[]
}

export interface WebContent {
  Path: string
  ContentType: string
  Size: number
  DataB64?: string
}

export interface Website {
  Name: string
  Contents: Record<string, WebContent>
  Size: number
}

export interface WGClientConfig {
  ServerPubKey: string
  ClientPrivateKey: string
  ClientPubKey: string
  ClientIP: string
}

export interface WGTCPForwarder {
  ID: number
  LocalAddr: string
  RemoteAddr: string
}

export interface WGSocksServer {
  ID: number
  LocalAddr: string
}

export interface Operator {
  Name: string
  FirstContact: string
  Sessions: number
  CanCleanup: boolean
}

export interface OperatorPresence {
  name: string
  online: boolean
}

export interface Canary {
  ImplantName: string
  Domain: string
  Triggered: boolean
  FirstTriggered?: string
  LatestTrigger?: string
  Count: number
}

export interface Credential {
  ID: number
  Username: string
  Plaintext: string
  Hash: string
  HashType: string
  Realm: string
  Collection: string
}

export interface Task {
  ID: number
  CreatedAt: string
  CompletedAt: string
  Description: string
  State: string
  Type: string
  SessionID: string
}

export interface GenerateResult {
  success: boolean
  message: string
  path?: string
  name?: string
  data?: string
  sha256?: string
  collision_with?: string
  pending?: boolean
  build_id?: string
}

export interface FileInfo {
  name: string
  path: string
  size: number
  isDir: boolean
}

export interface FileEntry {
  Name: string
  IsDir: boolean
  Size: number
  ModTime: number
  Mode: string
}

export interface DirView {
  Path: string
  Exists: boolean
  Files: FileEntry[]
}

export interface NetInterface {
  Index: number
  Name: string
  MAC: string
  IPAddresses: string[]
}

export interface ProcessInfo {
  PID: number
  PPID: number
  Executable: string
  Owner: string
  SessionID: number
  CmdLine: string[]
}

export interface SockEntry {
  Protocol: string
  LocalAddr: string
  LocalPort: number
  RemoteAddr: string
  RemotePort: number
  State: string
  UID: number
  ProcessName: string
}

export interface EnvVar {
  Key: string
  Value: string
}

export interface ExecResult {
  Status: number
  Stdout: string
  Stderr: string
  PID: number
}

export interface WindowsPrivilege {
  Name: string
  Description: string
  Enabled: boolean
  EnabledByDefault: boolean
  Removed: boolean
  UsedForAccess: boolean
}

export interface NetConnPivot {
  PeerID: number
  RemoteAddress: string
}

export interface PivotListener {
  ID: number
  Type: string
  BindAddress: string
  Pivots: NetConnPivot[]
}

export interface PivotGraphEntry {
  PeerID: number
  Name: string
  SessionID: string
  Hostname: string
  Username: string
  OS: string
  Transport: string
  RemoteAddress: string
  Children: PivotGraphEntry[]
}

export interface SSHCommandResult {
  StdOut: string
  StdErr: string
}

export interface CallExtensionResult {
  Output: string
  ServerStore: boolean
}

export interface MsfStager {
  FileName: string
  DataB64: string
  Size: number
}

export interface PortForward {
  LocalAddr: string
  LocalPort: number
  Host: string
  Port: number
  SessionID: string
}

export interface RportFwdListener {
  ID: number
  BindAddress: string
  BindPort: number
  ForwardAddress: string
  ForwardPort: number
}

export interface WasmExecResult {
  success: boolean
  name: string
  stdout?: string
  stderr?: string
  exit_code: number
  loot_id?: string
  pipe?: boolean
  warning?: string
  async?: boolean
  task_id?: string
  beacon_id?: string
}

export interface OperatorNote {
  uuid: string
  kind: string
  tags: string[]
  comment: string
  campaign: string
  updated_at: string
}

export interface OperatorLock {
  session_id: string
  user: string
  operator: string
  since: string
}

export interface OperatorReaction {
  id: number
  event_type: string
  commands: string[]
}

export interface OperatorAuditEntry {
  time: string
  user: string
  operator: string
  method: string
  path: string
  action: string
  status: number
}

export interface OperatorReactionHit {
  time: string
  event_type: string
  command: string
  target: string
  result: string
  skipped?: boolean
}

export interface BeaconTask {
  ID: string
  BeaconID: string
  CreatedAt: number
  State: string
  SentAt: number
  CompletedAt: number
  Description: string
  ResponseB64?: string
}

export interface QueuedTask {
  success?: boolean
  async: boolean
  task_id: string
  beacon_id?: string
}

export interface SocksProxy {
  ID: number
  SessionID: string
  BindAddr: string
  BindPort: number
  Username: string
  Password: string
}

export interface ImplantProfile {
  Name: string
  Config?: ImplantConfigView
}

export interface ImplantConfigView {
  HTTPC2ConfigName?: string
  TrafficEncodersEnabled?: boolean
  LimitDomainJoined?: boolean
  LimitHostname?: string
  LimitUsername?: string
  LimitDatetime?: string
  LimitFileExists?: string
  LimitLocale?: string

  Name: string
  OS: string
  Arch: string
  Format: string
  Interval: number
  Jitter: number
  Obfuscate: boolean
  Debug: boolean
  Evasion: boolean
  MaxConnectionErrors: number
  IsBeacon: boolean
  BeaconInterval: number
  BeaconJitter: number
  C2: { URL: string }[]
  CanaryDomains?: string[]
  Exports?: string[]
}

export interface Alias {
  Name: string
  Version: string
  CommandName: string
  OriginalAuthor: string
  RepoURL: string
  Help: string
  Entrypoint: string
  AllowArgs: boolean
  DefaultArgs: string
  Platforms: string[]
  IsAssembly: boolean
  IsReflective: boolean
}

