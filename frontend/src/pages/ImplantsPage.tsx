import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import { base64ToBytes, triggerDownload } from '../lib/binary'
import { matchC2Job, parseC2Url } from '../lib/c2'
import { implantHashes, rememberImplantHash, shortHash } from '../lib/artifactHash'
import type { CompilerInfo, ExternalBuilder, ImplantBuild, ImplantConfig, ImplantProfile, Job, Session } from '../lib/types'
import C2JobStatus from '../components/C2JobStatus'
import ConfirmDialog from '../components/common/ConfirmDialog'
import { useToast } from '../components/common/Toast'
import './pages.css'

const OS_ARCHES: { os: string; arches: string[] }[] = [
  { os: 'windows', arches: ['amd64', '386', 'arm64'] },
  { os: 'linux', arches: ['amd64', '386', 'arm64', 'arm'] },
  { os: 'darwin', arches: ['amd64', 'arm64'] },
  { os: 'freebsd', arches: ['amd64', '386', 'arm64', 'arm'] },
]

const C2_TYPES = ['mtls', 'http', 'https', 'dns', 'wireguard']

// Per-OS output formats, mirroring sliver-client's format options. `service`
// is Windows-only; `shellcode` is Windows/Linux/macOS; `shared` applies to
// every OS. Sending an unsupported format to the server would either fail or
// get silently forced back to exe, so the dropdown only offers what the
// target OS actually supports.
const FORMATS: Record<string, string[]> = {
  windows: ['exe', 'service', 'shellcode', 'shared'],
  linux: ['exe', 'shared', 'shellcode'],
  darwin: ['exe', 'shared', 'shellcode'],
  freebsd: ['exe', 'shared'],
}

// Sliver names the WireGuard listener job "wg" while the build form calls the
// transport "wireguard"; the other transports share their job name.
function listenerJobName(type: string): string {
  return type === 'wireguard' ? 'wg' : type
}

function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      const result = reader.result as string
      resolve(result.split(',')[1] || '')
    }
    reader.onerror = reject
    reader.readAsDataURL(file)
  })
}

export default function ImplantsPage() {
  const [builds, setBuilds] = useState<ImplantBuild[]>([])
  const [profiles, setProfiles] = useState<ImplantProfile[]>([])
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [generating, setGenerating] = useState(false)
  const [profileName, setProfileName] = useState('')

  const [name, setName] = useState('OneDriveUpdater')
  const [os, setOs] = useState('windows')
  const [arch, setArch] = useState('amd64')
  const [format, setFormat] = useState('exe')
  const [c2Type, setC2Type] = useState('https')
  const [c2Host, setC2Host] = useState('127.0.0.1')
  const [c2Port, setC2Port] = useState('443')
  const [reconInterval, setReconInterval] = useState('60')
  const [jitter, setJitter] = useState('20')
  const [isBeacon, setIsBeacon] = useState(false)
  const [obfuscate, setObfuscate] = useState(true)
  const [debug, setDebug] = useState(false)
  const [evasion, setEvasion] = useState(false)
  const [sgnEnabled, setSgnEnabled] = useState(false)
  const [shellcodeEntropy, setShellcodeEntropy] = useState(2)
  const [replaceExisting, setReplaceExisting] = useState(false)
  const [continueLoaders, setContinueLoaders] = useState<{ name: string } | null>(null)
  const [httpC2Profile, setHttpC2Profile] = useState('default')
  const [httpC2Profiles, setHttpC2Profiles] = useState<string[]>(['default'])
  const [trafficEncodersEnabled, setTrafficEncodersEnabled] = useState(false)
  const [trafficEncoders, setTrafficEncoders] = useState<string[]>([])
  const [selectedEncoders, setSelectedEncoders] = useState<string[]>([])
  const [limitDomainJoined, setLimitDomainJoined] = useState(false)
  const [limitHostname, setLimitHostname] = useState('')
  const [limitUsername, setLimitUsername] = useState('')
  const [limitDatetime, setLimitDatetime] = useState('')
  const [limitFileExists, setLimitFileExists] = useState('')
  const [limitLocale, setLimitLocale] = useState('')
  const [externalBuilderName, setExternalBuilderName] = useState('')
  const [canaryDomains, setCanaryDomains] = useState('')
  const [spoofBuildName, setSpoofBuildName] = useState('')
  const [spoofSource, setSpoofSource] = useState<File | null>(null)
  const [spoofIcon, setSpoofIcon] = useState<File | null>(null)
  const [spoofing, setSpoofing] = useState(false)
  const [hashes, setHashes] = useState<Record<string, string>>(() => implantHashes())
  const [lastHash, setLastHash] = useState<{ name: string; sha256: string; collision?: string } | null>(null)
  const [extBuilders, setExtBuilders] = useState<ExternalBuilder[]>([])
  const [serviceNameHint, setServiceNameHint] = useState('OneDrive Updator Service')
  const [serviceDescHint, setServiceDescHint] = useState('Provides update support for Microsoft OneDrive.')
  const [deleting, setDeleting] = useState<{ kind: 'build' | 'profile'; name: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [compiler, setCompiler] = useState<CompilerInfo | null>(null)
  const [sessions, setSessions] = useState<Session[]>([])
  const [jobs, setJobs] = useState<Job[]>([])
  const { t } = useTranslation()
  const toast = useToast()

  const osSummary = useMemo(() => {
    const m = new Map<string, number>()
    for (const b of builds) {
      const key = b.OS || 'unknown'
      m.set(key, (m.get(key) || 0) + 1)
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1])
  }, [builds])

  const load = async () => {
    try {
      const data = await api.builders()
      setBuilds(data.builders || [])
      setError('')
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const loadProfiles = async () => {
    try {
      const data = await api.implantProfiles()
      setProfiles(data.profiles || [])
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const loadCompiler = async () => {
    try {
      setCompiler(await api.compiler())
    } catch {
      setCompiler(null)
    }
  }

  const loadDetect = async () => {
    try {
      const [s, j, eb] = await Promise.all([api.sessions(), api.jobs(), api.externalBuilders()])
      setSessions(s.sessions || [])
      setJobs(j.jobs || [])
      setExtBuilders(eb.builders || [])
    } catch {
      // best-effort: keep the previous detection when the server is unreachable
    }
  }

  const recordHash = (name: string, sha256?: string, collision?: string) => {
    if (!sha256 || !name) return
    const coll = rememberImplantHash(name, sha256) || collision
    setHashes(implantHashes())
    setLastHash({ name, sha256, collision: coll })
  }

  const loadOpsecOptions = async () => {
    try {
      const [profiles, encoders] = await Promise.all([api.httpC2Profiles(), api.trafficEncoders()])
      const names = (profiles.profiles || []).map((p) => p.name).filter(Boolean)
      setHttpC2Profiles(names.length ? names : ['default'])
      if (names.length && !names.includes(httpC2Profile)) setHttpC2Profile(names[0])
      setTrafficEncoders((encoders.encoders || []).map((e) => e.name))
    } catch {
      setHttpC2Profiles(['default'])
      setTrafficEncoders([])
    }
  }

  useEffect(() => {
    load()
    loadProfiles()
    loadCompiler()
    loadDetect()
    loadOpsecOptions()
    const t = setInterval(load, 3000)
    const td = setInterval(loadDetect, 5000)
    return () => {
      clearInterval(t)
      clearInterval(td)
    }
  }, [])

  const detectedC2 = useMemo(() => {
    const session = sessions.find((s) => s.ActiveC2)
    const host = session ? parseC2Url(session.ActiveC2).host : ''
    const typeName = listenerJobName(c2Type)
    const match = jobs.find((j) => j.Name.toLowerCase() === typeName)
    const fallback = jobs[0]
    const useJob = match || fallback
    return {
      host,
      port: match ? String(match.Port) : '',
      anyPort: useJob ? String(useJob.Port) : '',
      source: useJob?.Name || '',
      match: !!match,
    }
  }, [sessions, jobs, c2Type])

  useEffect(() => {
    if (c2Host === '127.0.0.1' && detectedC2.host) setC2Host(detectedC2.host)
    if (c2Port === '8888' && detectedC2.port) setC2Port(detectedC2.port)
  }, [detectedC2, c2Host, c2Port])

  const currentOS = OS_ARCHES.find((o) => o.os === os)
  const formatOptions = FORMATS[os] || ['exe']

  const formatLabel = (f: string) =>
    f === 'exe'
      ? 'EXE'
      : f === 'service'
        ? t('implants.formatService')
        : f === 'shellcode'
          ? t('implants.formatShellcode')
          : t('implants.formatShared')

  const buildConfig = (): Partial<ImplantConfig> => ({
    name,
    os,
    arch,
    format,
    target: os,
    transport: c2Type,
    c2: [{ address: `${c2Host}:${c2Port}`, protocol: c2Type }],
    mtls: c2Type === 'mtls',
    http: c2Type === 'http' || c2Type === 'https',
    dns: c2Type === 'dns',
    wireguard: c2Type === 'wireguard',
    interval: Number(reconInterval),
    jitter: Number(jitter),
    is_beacon: isBeacon,
    debug,
    evasion,
    obfuscate,
    maxConnectionErrors: 1000,
    limitDomainJoined,
    http_c2_profile: httpC2Profile || 'default',
    traffic_encoders_enabled: trafficEncodersEnabled,
    traffic_encoders: trafficEncodersEnabled ? selectedEncoders : [],
    limit_hostname: limitHostname || undefined,
    limit_username: limitUsername || undefined,
    limit_datetime: limitDatetime || undefined,
    limit_file_exists: limitFileExists || undefined,
    limit_locale: limitLocale || undefined,
    external_builder_name: externalBuilderName || undefined,
    sgn_enabled: format === 'shellcode' ? sgnEnabled : false,
    shellcode_entropy: format === 'shellcode' ? shellcodeEntropy : undefined,
    shellcode_encoder: format === 'shellcode' && sgnEnabled ? 'SHIKATA_GA_NAI' : undefined,
    replace_existing: replaceExisting,
    canary_domains:
      externalBuilderName || !canaryDomains
        ? undefined
        : canaryDomains.split(/[,\s]+/).map((d) => d.trim()).filter(Boolean),
  })

  const nameAlreadyUsed = useMemo(() => {
    const n = name.trim().toLowerCase()
    if (!n) return false
    const base = n.replace(/\.[^.]+$/, '')
    return builds.some((b) => {
      const bn = (b.Name || '').toLowerCase()
      const bb = bn.replace(/\.[^.]+$/, '')
      return bn === n || bb === base || bn === base || bb === n
    })
  }, [builds, name])

  const typedC2Url = `${c2Type}://${c2Host}:${c2Port}`
  const typedC2Missing =
    jobs.length > 0 && Boolean(c2Host.trim()) && Boolean(c2Port.trim()) && !matchC2Job(typedC2Url, jobs)

  const saveProfile = async () => {
    if (!profileName) return
    setMessage('')
    try {
      await api.saveImplantProfile({ name: profileName, is_beacon: isBeacon, config: buildConfig() })
      setMessage(t('profiles.saved', { name: profileName }))
      setProfileName('')
      loadProfiles()
    } catch (e) {
      setMessage(t('profiles.failed', { msg: (e as Error).message }))
    }
  }

  const deleteProfile = async (p: ImplantProfile) => {
    setBusy(true)
    try {
      await api.deleteImplantProfile(p.Name)
      setDeleting(null)
      toast.push('success', t('profiles.deleted', { name: p.Name }))
      loadProfiles()
    } catch (e) {
      toast.push('error', t('profiles.failed', { msg: (e as Error).message }))
    } finally {
      setBusy(false)
    }
  }

  // 复用:将 profile 的配置载入生成表单
  const loadProfile = (p: ImplantProfile) => {
    const cfg = p.Config
    if (!cfg) return
    setName(p.Name)
    if (cfg.OS) setOs(cfg.OS)
    if (cfg.Arch) setArch(cfg.Arch)
    if (cfg.Format) setFormat(cfg.Format)
    const c2 = cfg.C2?.[0]
    if (c2?.URL) {
      const { proto, host, port } = parseC2Url(c2.URL)
      setC2Type(proto)
      if (host) setC2Host(host)
      if (port) setC2Port(port)
    }
    if (cfg.Interval) setReconInterval(String(cfg.Interval))
    if (cfg.Jitter !== undefined) setJitter(String(cfg.Jitter))
    setIsBeacon(!!cfg.IsBeacon)
    if (cfg.Obfuscate !== undefined) setObfuscate(cfg.Obfuscate)
    if (cfg.Debug !== undefined) setDebug(cfg.Debug)
    if (cfg.Evasion !== undefined) setEvasion(cfg.Evasion)
    if (cfg.HTTPC2ConfigName) setHttpC2Profile(cfg.HTTPC2ConfigName)
    if (cfg.TrafficEncodersEnabled !== undefined) setTrafficEncodersEnabled(cfg.TrafficEncodersEnabled)
    if (cfg.LimitDomainJoined !== undefined) setLimitDomainJoined(cfg.LimitDomainJoined)
    setLimitDatetime(cfg.LimitDatetime || '')
    setLimitFileExists(cfg.LimitFileExists || '')
    setLimitLocale(cfg.LimitLocale || '')
    setCanaryDomains((cfg.CanaryDomains || []).join(', '))
    setMessage(t('profiles.loaded', { name: p.Name }))
  }

  const generate = async () => {
    setGenerating(true)
    setMessage('')
    setContinueLoaders(null)
    try {
      const cfg = buildConfig()
      const res = await api.generate(cfg)
      if (res.pending) {
        setMessage(t('implants.pendingExternal', { id: res.build_id || '' }))
      } else {
        if (res.success && res.data) {
          triggerDownload(res.name || name, base64ToBytes(res.data))
        }
        if (res.success) recordHash(res.name || name, res.sha256, res.collision_with)
        if (res.success && (format === 'shared' || format === 'shellcode')) {
          setContinueLoaders({ name: res.name || name })
          setMessage(t('implants.generatedContinue', { msg: res.message }))
        } else {
          setMessage(
            res.success ? t('implants.generated', { msg: res.message }) : t('implants.failed', { msg: res.message }),
          )
        }
      }
      load()
    } catch (e) {
      setMessage(t('implants.failed', { msg: (e as Error).message }))
    } finally {
      setGenerating(false)
    }
  }

  const downloadBuild = async (b: ImplantBuild) => {
    setMessage('')
    try {
      const res = await api.regenerate(b.Name)
      if (res.data) {
        triggerDownload(res.name || b.Name, base64ToBytes(res.data))
        recordHash(res.name || b.Name, res.sha256, res.collision_with)
      } else {
        setMessage(t('implants.failed', { msg: 'no file data returned' }))
      }
    } catch (e) {
      setMessage(t('implants.failed', { msg: (e as Error).message }))
    }
  }

  const regenerateBuild = async (b: ImplantBuild) => {
    setMessage('')
    try {
      const res = await api.regenerate(b.Name)
      if (res.success) recordHash(res.name || b.Name, res.sha256, res.collision_with)
      setMessage(
        res.success ? t('implants.regenerated', { name: b.Name }) : t('implants.failed', { msg: res.message }),
      )
      load()
    } catch (e) {
      setMessage(t('implants.failed', { msg: (e as Error).message }))
    }
  }

  const deleteBuild = async (b: ImplantBuild) => {
    setBusy(true)
    try {
      await api.deleteImplantBuild(b.Name)
      setDeleting(null)
      toast.push('success', t('implants.deleted', { name: b.Name }))
      load()
    } catch (e) {
      toast.push('error', t('implants.failed', { msg: (e as Error).message }))
    } finally {
      setBusy(false)
    }
  }

  const windowsPeBuilds = builds.filter(
    (b) => (b.OS || b.ImplantConfig?.OS || '').toLowerCase() === 'windows',
  )

  const spoofApply = async () => {
    const target = spoofBuildName || windowsPeBuilds[0]?.Name || ''
    if (!target || !spoofSource) return
    setSpoofing(true)
    try {
      const source_b64 = await fileToBase64(spoofSource)
      const icon_b64 = spoofIcon ? await fileToBase64(spoofIcon) : undefined
      await api.spoofMetadata(target, {
        source_name: spoofSource.name,
        source_b64,
        icon_name: spoofIcon?.name,
        icon_b64,
      })
      toast.push('success', t('implants.spoofDone', { name: target }))
    } catch (e) {
      setMessage(t('implants.failed', { msg: (e as Error).message }))
    } finally {
      setSpoofing(false)
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="page-title">{t('implants.title')}</div>
          <div className="page-sub">{t('implants.sub', { count: builds.length })}</div>
        </div>
        <div className="toolbar">
          <button type="button" className="btn" onClick={load}>
            {t('common.refresh')}
          </button>
        </div>
      </div>
      {error && <div className="error-banner">{error}</div>}
      {message && (
        <div className="success-banner">
          {message}
          {continueLoaders && (
            <>
              {' '}
              <Link to={`/loaders?build=${encodeURIComponent(continueLoaders.name)}`}>
                {t('implants.continueLoaders')}
              </Link>
            </>
          )}
        </div>
      )}
      {lastHash && (
        <div className="success-banner">
          {t('implants.lastHash', { name: lastHash.name, hash: shortHash(lastHash.sha256) })}
          {lastHash.collision && (
            <div className="form-hint warn-hint">{t('implants.collision', { other: lastHash.collision })}</div>
          )}
        </div>
      )}

      {compiler && (
        <div className="compiler-strip">
          <span className="compiler-tag">
            {t('implants.compiler')}: {compiler.GOOS}/{compiler.GOARCH}
          </span>
          <span className="compiler-tag mono">{compiler.Targets?.length || 0} targets</span>
          <span className="compiler-tag mono">{compiler.CrossCompilers?.length || 0} cross-compilers</span>
          {compiler.CrossCompilers?.map((cc) => (
            <span key={`${cc.TargetGOOS}/${cc.TargetGOARCH}`} className="compiler-tag mono">
              {cc.TargetGOOS}/{cc.TargetGOARCH}
            </span>
          ))}
        </div>
      )}
      {extBuilders.length > 0 && (
        <div className="compiler-strip">
          <span className="compiler-tag">{t('implants.extBuilders')}</span>
          {extBuilders.map((b) => (
            <span key={`${b.name}-${b.operator_name}`} className="compiler-tag mono" title={(b.targets || []).join(', ')}>
              {t('implants.extBuilderLine', {
                name: b.name || 'builder',
                operator: b.operator_name || '—',
                target: `${b.goos}/${b.goarch}`,
              })}
            </span>
          ))}
        </div>
      )}

      {builds.length > 0 && (
        <div className="dash-stats build-summary">
          <button type="button" className="dash-stat" onClick={() => {}}>
            <div className="dash-stat-value mono">{builds.length}</div>
            <div className="dash-stat-label">{t('implants.totalBuilds')}</div>
          </button>
          {osSummary.map(([osName, count]) => (
            <button type="button" key={osName} className="dash-stat" onClick={() => {}}>
              <div className="dash-stat-value mono">{count}</div>
              <div className="dash-stat-label">{osName}</div>
            </button>
          ))}
        </div>
      )}

      <div className="card card-flush">
        <table className="data">
          <thead>
            <tr>
              <th>{t('implants.thName')}</th>
              <th>{t('implants.thOsArch')}</th>
              <th>{t('implants.thFormat')}</th>
              <th>{t('implants.thHash')}</th>
              <th>{t('implants.thC2')}</th>
              <th>{t('implants.thInterval')}</th>
              <th>{t('implants.thObfuscated')}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {builds.length === 0 && (
              <tr>
                <td colSpan={8} className="empty">
                  {t('implants.empty')}
                </td>
              </tr>
            )}
            {builds.map((b) => (
              <tr key={b.Name}>
                <td className="mono">{b.Name}</td>
                <td>
                  <span className="badge blue">
                    {b.OS}/{b.Arch}
                  </span>
                </td>
                <td>{b.ImplantConfig?.Format || '-'}</td>
                <td className="mono" title={hashes[b.Name] || ''}>
                  {hashes[b.Name] ? shortHash(hashes[b.Name]) : '—'}
                </td>
                <td>
                  {(b.ImplantConfig?.C2 || []).length === 0
                    ? '-'
                    : (b.ImplantConfig?.C2 || []).map((c) => (
                        <div key={c.URL} className="c2-cell">
                          <span className="mono">{c.URL}</span>
                          <C2JobStatus url={c.URL} jobs={jobs} />
                        </div>
                      ))}
                </td>
                <td className="mono">
                  {b.ImplantConfig?.IsBeacon ? `${t('implants.beaconShort')} ` : ''}
                  {b.ImplantConfig?.Interval}s / {b.ImplantConfig?.Jitter}%
                </td>
                <td>{b.ImplantConfig?.Obfuscate ? t('common.yes') : t('common.no')}</td>
                <td>
                  <div className="fs-actions">
                    <button type="button" className="btn sm" onClick={() => downloadBuild(b)}>
                      {t('implants.download')}
                    </button>
                    <button type="button" className="btn sm" onClick={() => regenerateBuild(b)}>
                      {t('implants.regenerate')}
                    </button>
                    {(() => {
                      const fmt = (b.ImplantConfig?.Format || '').toUpperCase()
                      const loaderFmt =
                        fmt.includes('SHELLCODE') || fmt.includes('SHARED') || fmt === 'SHARED_LIB'
                      return loaderFmt ? (
                        <Link
                          className="btn sm"
                          to={`/loaders?build=${encodeURIComponent(b.Name)}`}
                        >
                          {t('implants.sendToLoaders')}
                        </Link>
                      ) : null
                    })()}
                    <button type="button" className="btn sm danger" onClick={() => setDeleting({ kind: 'build', name: b.Name })}>
                      {t('profiles.delete')}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card">
        <div className="card-title">{t('implants.genTitle')}</div>
        <div className="form-hint" style={{ marginBottom: 10 }}>
          {t('implants.opsecHint')}
        </div>
        <div className="form-grid">
          <div className="field">
            <label>{t('implants.name')}</label>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="OneDriveUpdater" />
          </div>
          <div className="field">
            <label>{t('implants.os')}</label>
            <select
              value={os}
              onChange={(e) => {
                const next = e.target.value
                setOs(next)
                setArch(OS_ARCHES.find((o) => o.os === next)?.arches[0] || 'amd64')
                const formats = FORMATS[next] || ['exe']
                if (!formats.includes(format)) setFormat(formats[0])
              }}
            >
              {OS_ARCHES.map((o) => (
                <option key={o.os} value={o.os}>
                  {o.os}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label>{t('implants.arch')}</label>
            <select value={arch} onChange={(e) => setArch(e.target.value)}>
              {currentOS?.arches.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label>{t('implants.format')}</label>
            <select value={format} onChange={(e) => setFormat(e.target.value)}>
              {formatOptions.map((f) => (
                <option key={f} value={f}>
                  {formatLabel(f)}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label>{t('implants.c2Type')}</label>
            <select value={c2Type} onChange={(e) => setC2Type(e.target.value)}>
              {C2_TYPES.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label>{t('implants.c2Host')}</label>
            <input value={c2Host} onChange={(e) => setC2Host(e.target.value)} />
          </div>
          <div className="field">
            <label>{t('implants.c2Port')}</label>
            <input value={c2Port} onChange={(e) => setC2Port(e.target.value)} />
          </div>
          <div className="field check">
            <label>
              <input type="checkbox" checked={isBeacon} onChange={(e) => setIsBeacon(e.target.checked)} />
              {t('implants.isBeacon')}
            </label>
          </div>
          <div className="field">
            <label>{isBeacon ? t('implants.beaconInterval') : t('implants.interval')}</label>
            <input type="number" value={reconInterval} onChange={(e) => setReconInterval(e.target.value)} />
          </div>
          <div className="field">
            <label>{t('implants.jitter')}</label>
            <input type="number" value={jitter} onChange={(e) => setJitter(e.target.value)} />
          </div>
          {isBeacon && (
            <div className="form-hint span-all">{t('implants.beaconHint')}</div>
          )}
          <div className="field check">
            <label>
              <input type="checkbox" checked={obfuscate} onChange={(e) => setObfuscate(e.target.checked)} />
              {t('implants.obfuscate')}
            </label>
          </div>
          <div className="field check">
            <label>
              <input type="checkbox" checked={debug} onChange={(e) => setDebug(e.target.checked)} />
              {t('implants.debug')}
            </label>
          </div>
          <div className="field check">
            <label>
              <input type="checkbox" checked={evasion} onChange={(e) => setEvasion(e.target.checked)} />
              {t('implants.evasion')}
            </label>
          </div>
          {format === 'shellcode' && (
            <>
              <div className="field check">
                <label>
                  <input type="checkbox" checked={sgnEnabled} onChange={(e) => setSgnEnabled(e.target.checked)} />
                  {t('implants.sgnEnabled')}
                </label>
              </div>
              <div className="field">
                <label>{t('implants.shellcodeEntropy')}</label>
                <select
                  value={shellcodeEntropy}
                  onChange={(e) => setShellcodeEntropy(Number(e.target.value))}
                >
                  <option value={1}>{t('implants.entropyNone')}</option>
                  <option value={2}>{t('implants.entropyNames')}</option>
                  <option value={3}>{t('implants.entropyEncrypt')}</option>
                </select>
              </div>
            </>
          )}
          {(c2Type === 'http' || c2Type === 'https') && (
            <div className="field">
              <label>{t('implants.httpC2Profile')}</label>
              <select value={httpC2Profile} onChange={(e) => setHttpC2Profile(e.target.value)}>
                {httpC2Profiles.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </div>
          )}
          <div className="field check">
            <label>
              <input
                type="checkbox"
                checked={trafficEncodersEnabled}
                onChange={(e) => setTrafficEncodersEnabled(e.target.checked)}
              />
              {t('implants.trafficEncoders')}
            </label>
          </div>
          {trafficEncodersEnabled && trafficEncoders.length > 0 && (
            <div className="field">
              <label>{t('implants.trafficEncoderList')}</label>
              <select
                multiple
                value={selectedEncoders}
                onChange={(e) =>
                  setSelectedEncoders(Array.from(e.target.selectedOptions).map((o) => o.value))
                }
                style={{ minHeight: 72 }}
              >
                {trafficEncoders.map((enc) => (
                  <option key={enc} value={enc}>
                    {enc}
                  </option>
                ))}
              </select>
            </div>
          )}
          <div className="field check">
            <label>
              <input
                type="checkbox"
                checked={limitDomainJoined}
                onChange={(e) => setLimitDomainJoined(e.target.checked)}
              />
              {t('implants.limitDomainJoined')}
            </label>
          </div>
          <div className="field">
            <label>{t('implants.limitHostname')}</label>
            <input
              value={limitHostname}
              onChange={(e) => setLimitHostname(e.target.value)}
              placeholder="DESKTOP-*"
            />
          </div>
          <div className="field">
            <label>{t('implants.limitUsername')}</label>
            <input value={limitUsername} onChange={(e) => setLimitUsername(e.target.value)} />
          </div>
          <div className="field">
            <label>{t('implants.limitDatetime')}</label>
            <input
              type="text"
              value={limitDatetime}
              onChange={(e) => setLimitDatetime(e.target.value)}
              placeholder="2025-12-31T23:59:59Z"
            />
          </div>
          <div className="form-hint span-all">{t('implants.limitDatetimeHint')}</div>
          <div className="field">
            <label>{t('implants.limitFileExists')}</label>
            <input
              value={limitFileExists}
              onChange={(e) => setLimitFileExists(e.target.value)}
              placeholder="C:\Windows\System32\notepad.exe"
            />
          </div>
          <div className="field">
            <label>{t('implants.limitLocale')}</label>
            <input
              value={limitLocale}
              onChange={(e) => setLimitLocale(e.target.value)}
              placeholder="en-US"
            />
          </div>
          <div className="field">
            <label>{t('implants.externalBuilder')}</label>
            <select value={externalBuilderName} onChange={(e) => setExternalBuilderName(e.target.value)}>
              <option value="">{t('implants.externalBuilderNone')}</option>
              {extBuilders.map((b) => (
                <option key={`${b.name}-${b.operator_name}`} value={b.name}>
                  {t('implants.extBuilderLine', {
                    name: b.name || 'builder',
                    operator: b.operator_name || '—',
                    target: `${b.goos}/${b.goarch}`,
                  })}
                </option>
              ))}
            </select>
          </div>
          <div className="form-hint span-all">{t('implants.externalBuilderHint')}</div>
          <div className="field span-all">
            <label>{t('implants.canaryDomains')}</label>
            <input
              value={canaryDomains}
              onChange={(e) => setCanaryDomains(e.target.value)}
              placeholder="cdn.example.com, updates.example.net"
            />
          </div>
          <div className="form-hint span-all">{t('implants.canaryHint')}</div>
          <div className="field check">
            <label>
              <input
                type="checkbox"
                checked={replaceExisting}
                onChange={(e) => setReplaceExisting(e.target.checked)}
              />
              {t('implants.replaceExisting')}
            </label>
          </div>
          <div className="field span-all form-actions">
            <button type="button" className="btn primary" onClick={generate} disabled={generating}>
              {generating ? t('implants.generating') : t('implants.generate')}
            </button>
          </div>
        </div>
        {nameAlreadyUsed && !replaceExisting && (
          <div className="form-hint warn-hint">
            {t('implants.nameTakenHint', { name })}
          </div>
        )}
        {format === 'service' && (
          <div className="form-hint" style={{ marginTop: 10 }}>
            <strong>{t('implants.serviceHintTitle')}</strong> {t('implants.serviceHintBody')}
            <div className="form-grid" style={{ marginTop: 8 }}>
              <div className="field">
                <label>{t('implants.serviceName')}</label>
                <input value={serviceNameHint} onChange={(e) => setServiceNameHint(e.target.value)} />
              </div>
              <div className="field">
                <label>{t('implants.serviceDesc')}</label>
                <input value={serviceDescHint} onChange={(e) => setServiceDescHint(e.target.value)} />
              </div>
            </div>
            <div style={{ marginTop: 6, color: 'var(--text-mute)', fontSize: 'var(--fs-sm)' }}>
              {t('implants.serviceHintNote', { name: serviceNameHint, desc: serviceDescHint })}
            </div>
          </div>
        )}
        {detectedC2.host && detectedC2.anyPort && (
          <div
            className="form-hint"
            style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}
          >
            <span>
              {detectedC2.match
                ? t('implants.detectedListener', {
                    name: detectedC2.source,
                    host: detectedC2.host,
                    port: detectedC2.port,
                  })
                : t('implants.detectedOther', {
                    type: c2Type,
                    name: detectedC2.source,
                    host: detectedC2.host,
                    port: detectedC2.anyPort,
                  })}
            </span>
            <button
              type="button"
              className="btn sm"
              onClick={() => {
                setC2Host(detectedC2.host)
                setC2Port(detectedC2.anyPort)
              }}
            >
              {t('common.use')}
            </button>
          </div>
        )}
        {typedC2Missing && (
          <div className="form-hint warn-hint" style={{ marginTop: 8 }}>
            {t('implants.typedC2Missing', { url: typedC2Url, type: c2Type })}
          </div>
        )}
        <div className="profile-save">
          <input
            className="profile-name-input"
            type="text"
            placeholder={t('profiles.profileName')}
            value={profileName}
            onChange={(e) => setProfileName(e.target.value)}
          />
          <button type="button" className="btn" onClick={saveProfile} disabled={!profileName}>
            {t('profiles.saveAs')}
          </button>
        </div>
      </div>

      <div className="card">
        <div className="card-title">{t('implants.spoofTitle')}</div>
        <div className="form-hint" style={{ marginBottom: 10 }}>
          {t('implants.spoofHint')}
        </div>
        {windowsPeBuilds.length === 0 ? (
          <div className="form-hint">{t('implants.spoofWindowsOnly')}</div>
        ) : (
          <div className="form-grid">
            <div className="field">
              <label>{t('implants.spoofPickBuild')}</label>
              <select
                value={spoofBuildName || windowsPeBuilds[0]?.Name || ''}
                onChange={(e) => setSpoofBuildName(e.target.value)}
              >
                {windowsPeBuilds.map((b) => (
                  <option key={b.Name} value={b.Name}>
                    {b.Name}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label>{t('implants.spoofSource')}</label>
              <input type="file" onChange={(e) => setSpoofSource(e.target.files?.[0] || null)} />
            </div>
            <div className="field">
              <label>{t('implants.spoofIcon')}</label>
              <input type="file" onChange={(e) => setSpoofIcon(e.target.files?.[0] || null)} />
            </div>
            <div className="field span-all form-actions">
              <button
                type="button"
                className="btn primary"
                onClick={spoofApply}
                disabled={spoofing || !spoofSource}
              >
                {t('implants.spoofApply')}
              </button>
            </div>
          </div>
        )}
      </div>

      {profiles.length > 0 && (
        <div className="card card-flush">
          <div className="card-title bar">
            {t('profiles.title')}
          </div>
          <table className="data">
            <thead>
              <tr>
                <th>{t('profiles.thName')}</th>
                <th>{t('profiles.thOsArch')}</th>
                <th>{t('profiles.thFormat')}</th>
                <th>{t('profiles.thC2')}</th>
                <th>{t('profiles.thInterval')}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {profiles.map((p) => (
                <tr key={p.Name}>
                  <td className="mono">{p.Name}</td>
                  <td>
                    <span className="badge blue">
                      {p.Config?.OS}/{p.Config?.Arch}
                    </span>
                  </td>
                  <td>{p.Config?.Format || '-'}</td>
                  <td className="mono">{p.Config?.C2?.map((c) => c.URL).join(', ') || '-'}</td>
                  <td className="mono">
                    {p.Config?.IsBeacon ? `${t('implants.beaconShort')} ` : ''}
                    {p.Config?.Interval}s / {p.Config?.Jitter}%
                  </td>
                  <td>
                    <div className="fs-actions">
                      <button type="button" className="btn sm" onClick={() => loadProfile(p)}>
                        {t('profiles.load')}
                      </button>
                      {(() => {
                        const fmt = (p.Config?.Format || '').toUpperCase()
                        const stageFmt = fmt.includes('SHELLCODE') || fmt.includes('SHARED')
                        return stageFmt ? (
                          <Link
                            className="btn sm"
                            to={`/loaders?tab=stage&profile=${encodeURIComponent(p.Name)}`}
                          >
                            {t('implants.sendToLoaders')}
                          </Link>
                        ) : null
                      })()}
                      <button type="button" className="btn sm danger" onClick={() => setDeleting({ kind: 'profile', name: p.Name })}>
                        {t('profiles.delete')}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ConfirmDialog
        open={!!deleting}
        title={deleting?.kind === 'build' ? t('implants.confirmDelete') : t('profiles.confirmDelete')}
        danger
        busy={busy}
        confirmLabel={t('profiles.delete')}
        onConfirm={() => {
          if (!deleting) return
          if (deleting.kind === 'build') {
            const b = builds.find((x) => x.Name === deleting.name)
            if (b) deleteBuild(b)
          } else {
            const p = profiles.find((x) => x.Name === deleting.name)
            if (p) deleteProfile(p)
          }
        }}
        onCancel={() => setDeleting(null)}
      >
        <p>{deleting ? t('implants.confirmDeleteBody', { name: deleting.name }) : ''}</p>
      </ConfirmDialog>
    </div>
  )
}
