import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import { base64ToBytes, bytesToBase64, triggerDownload } from '../lib/binary'
import { matchC2Job } from '../lib/c2'
import type { ImplantBuild, ImplantProfile, Job, ShellcodeEncoderArch } from '../lib/types'
import C2JobStatus from '../components/C2JobStatus'
import { useToast } from '../components/common/Toast'
import './pages.css'

type Tab = 'wrap' | 'tools' | 'stage' | 'fork'

const LS_KEY = 'sliverui-loaders-opts'

type SavedOpts = {
  encoder: string
  arch: string
  os: string
  iterations: number
  functionName: string
  hideConsole: boolean
  xorKey: string
  persistence: string
  persistName: string
}

const DEFAULTS: SavedOpts = {
  encoder: 'NONE',
  arch: 'amd64',
  os: 'windows',
  iterations: 1,
  functionName: 'StartW',
  hideConsole: true,
  xorKey: '',
  persistence: 'off',
  persistName: 'RuntimeBroker',
}

function loadOpts(): SavedOpts {
  try {
    const raw = localStorage.getItem(LS_KEY)
    if (raw) return { ...DEFAULTS, ...JSON.parse(raw) }
  } catch {
    /* ignore */
  }
  return { ...DEFAULTS }
}

function normOS(s: string): string {
  const x = (s || '').toLowerCase()
  if (x.startsWith('win')) return 'windows'
  if (x === 'darwin' || x === 'macos' || x === 'osx' || x === 'mac') return 'darwin'
  if (x === 'linux') return 'linux'
  return x || 'windows'
}

function normArch(s: string): string {
  const x = (s || '').toLowerCase()
  if (x === 'x86_64' || x === 'x64' || x === 'amd64') return 'amd64'
  if (x === 'x86' || x === 'i386' || x === 'i686' || x === '386') return '386'
  if (x === 'aarch64' || x === 'arm64') return 'arm64'
  if (x === 'arm' || x.startsWith('armv')) return 'arm'
  return x || 'amd64'
}

function persistOptions(os: string): { value: string; key: string }[] {
  if (os === 'linux') {
    return [
      { value: 'off', key: 'persistNone' },
      { value: 'systemd_user', key: 'persistSystemd' },
      { value: 'cron', key: 'persistCron' },
      { value: 'all', key: 'persistAllLinux' },
    ]
  }
  if (os === 'darwin') {
    return [
      { value: 'off', key: 'persistNone' },
      { value: 'launchagent', key: 'persistLaunch' },
    ]
  }
  return [
    { value: 'off', key: 'persistNone' },
    { value: 'runkey_hkcu', key: 'persistRunkey' },
    { value: 'schtask_logon', key: 'persistSchtask' },
    { value: 'startup_lnk', key: 'persistLnk' },
    { value: 'all', key: 'persistAllWindows' },
  ]
}

function persistAllowed(os: string, method: string): boolean {
  return persistOptions(os).some((p) => p.value === method)
}

function outName(name: string, os: string): string {
  const base = (name || 'payload').replace(/\.[^.]+$/, '').replace(/[^\w.-]+/g, '_') || 'payload'
  return os === 'windows' ? `${base}_loader.exe` : `${base}_loader`
}

async function sha256Hex(buf: ArrayBuffer): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', buf)
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

function formatLabel(b: ImplantBuild): string {
  const fmt = b.ImplantConfig?.Format || ''
  return `${b.Name} (${b.OS || '?'}/${b.Arch || '?'}/${fmt || '?'})`
}

function isLoaderFormat(b: ImplantBuild): boolean {
  const f = (b.ImplantConfig?.Format || '').toUpperCase()
  return f.includes('SHELLCODE') || f.includes('SHARED') || f === 'SHARED_LIB'
}

function isShared(b: ImplantBuild | undefined): boolean {
  const f = (b?.ImplantConfig?.Format || '').toUpperCase()
  return f.includes('SHARED')
}

export default function LoadersPage() {
  const { t } = useTranslation()
  const toast = useToast()
  const [params] = useSearchParams()
  const initialTab = params.get('tab')
  const [tab, setTab] = useState<Tab>(() =>
    initialTab === 'tools' || initialTab === 'stage' || initialTab === 'wrap' || initialTab === 'fork'
      ? initialTab
      : 'wrap',
  )

  const [builds, setBuilds] = useState<ImplantBuild[]>([])
  const [profiles, setProfiles] = useState<ImplantProfile[]>([])
  const [jobs, setJobs] = useState<Job[]>([])
  const [encoderMap, setEncoderMap] = useState<ShellcodeEncoderArch[]>([])
  const [sourceName, setSourceName] = useState(params.get('build') || '')
  const [blobB64, setBlobB64] = useState('')
  const [blobSize, setBlobSize] = useState(0)
  const [blobHash, setBlobHash] = useState('')
  const [busy, setBusy] = useState(false)
  const [busyMsg, setBusyMsg] = useState('')
  const [error, setError] = useState('')
  const [opts, setOpts] = useState<SavedOpts>(loadOpts)
  const [badChars, setBadChars] = useState('')
  const [doRdi, setDoRdi] = useState(false)
  const [forkRoot, setForkRoot] = useState('')
  const [forkModule, setForkModule] = useState('github.com/labhost/implant')
  const [forkBranding, setForkBranding] = useState(true)
  const [forkProto, setForkProto] = useState(false)
  const [forkGenerator, setForkGenerator] = useState(true)
  const [forkReport, setForkReport] = useState<{
    files?: number
    dry_run?: boolean
    hits?: Record<string, number>
    changed?: string[]
    next?: string[]
    note?: string
    needs_ui_build?: boolean
    error?: string
  } | null>(null)
  const [lastClean, setLastClean] = useState<{
    replaced?: string[]
    remaining?: string[]
    note?: string
    export?: string
  } | null>(null)
  const [stageProfile, setStageProfile] = useState(() => params.get('profile') || '')
  const [stageURL, setStageURL] = useState('tcp://0.0.0.0:8443')
  const [aesKey, setAesKey] = useState('')
  const [aesIV, setAesIV] = useState('0000000000000000')
  const [compress, setCompress] = useState('')
  const [lastKeys, setLastKeys] = useState<{ aes?: string; iv?: string; rc4?: string; job?: number } | null>(null)
  const [autoLoaded, setAutoLoaded] = useState(false)

  useEffect(() => {
    localStorage.setItem(LS_KEY, JSON.stringify(opts))
  }, [opts])

  useEffect(() => {
    if (!persistAllowed(opts.os, opts.persistence)) {
      setOpts((o) => ({ ...o, persistence: 'off' }))
    }
  }, [opts.os, opts.persistence])

  const refresh = useCallback(async () => {
    try {
      const [b, p, e, j] = await Promise.all([
        api.builders(),
        api.implantProfiles(),
        api.shellcodeEncoders().catch(() => ({ encoders: [] as ShellcodeEncoderArch[] })),
        api.jobs().catch(() => ({ jobs: [] as Job[] })),
      ])
      setBuilds(b.builders || [])
      setProfiles(p.profiles || [])
      setEncoderMap(e.encoders || [])
      setJobs(j.jobs || [])
      setError('')
    } catch (err) {
      setError((err as Error).message)
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  const setBlob = useCallback(async (b64: string) => {
    setBlobB64(b64)
    const buf = base64ToBytes(b64)
    setBlobSize(buf.byteLength)
    setBlobHash(await sha256Hex(buf))
  }, [])

  const applyBuildMeta = useCallback((b: ImplantBuild | undefined) => {
    if (!b) return
    setDoRdi(isShared(b))
    const exp = b.ImplantConfig?.Exports?.[0]
    setOpts((o) => ({
      ...o,
      os: normOS(b.OS || b.ImplantConfig?.OS || o.os),
      arch: normArch(b.Arch || b.ImplantConfig?.Arch || o.arch),
      functionName: exp || o.functionName,
    }))
  }, [])

  useEffect(() => {
    const build = params.get('build')
    if (!build || autoLoaded || builds.length === 0) return
    if (!builds.some((b) => b.Name === build)) return
    setSourceName(build)
    setAutoLoaded(true)
    void (async () => {
      setBusy(true)
      setBusyMsg(t('loaders.loading'))
      try {
        const res = await api.regenerate(build)
        if (!res.data) throw new Error('no file data returned')
        await setBlob(res.data)
        applyBuildMeta(builds.find((x) => x.Name === build))
      } catch (err) {
        setError((err as Error).message)
      } finally {
        setBusy(false)
        setBusyMsg('')
      }
    })()
  }, [params, builds, autoLoaded, setBlob, applyBuildMeta, t])

  const loaderBuilds = useMemo(() => builds.filter(isLoaderFormat), [builds])
  const encoderNames = useMemo(() => {
    const set = new Set<string>(['NONE'])
    for (const row of encoderMap) Object.keys(row.encoders || {}).forEach((n) => set.add(n))
    ;['SHIKATA_GA_NAI', 'XOR', 'XOR_DYNAMIC'].forEach((n) => set.add(n))
    return [...set]
  }, [encoderMap])

  const selectedBuild = useMemo(
    () => loaderBuilds.find((b) => b.Name === sourceName),
    [loaderBuilds, sourceName],
  )
  const sharedSource = isShared(selectedBuild)
  const outputName = outName(sourceName, opts.os)
  const selectedC2s = selectedBuild?.ImplantConfig?.C2 || []
  const selectedIsBeacon = Boolean(selectedBuild?.ImplantConfig?.IsBeacon)
  const missingC2 = selectedC2s.filter((c) => c.URL && !matchC2Job(c.URL, jobs))
  const loopbackC2 = selectedC2s.some((c) => /127\.0\.0\.1|localhost/i.test(c.URL || ''))

  const loadBuild = async () => {
    if (!sourceName) return
    setBusy(true)
    setBusyMsg(t('loaders.loading'))
    setError('')
    try {
      const res = await api.regenerate(sourceName)
      if (!res.data) throw new Error('no file data returned')
      await setBlob(res.data)
      applyBuildMeta(builds.find((x) => x.Name === sourceName))
      toast.push('success', t('loaders.loadedBuild', { name: sourceName, size: base64ToBytes(res.data).byteLength }))
    } catch (err) {
      setError((err as Error).message)
      toast.push('error', (err as Error).message)
    } finally {
      setBusy(false)
      setBusyMsg('')
    }
  }

  const onUpload = async (file: File | null) => {
    if (!file) return
    setBusy(true)
    try {
      const buf = await file.arrayBuffer()
      await setBlob(bytesToBase64(new Uint8Array(buf)))
      setSourceName(file.name)
      toast.push('success', t('loaders.uploaded', { name: file.name, size: buf.byteLength }))
    } catch (err) {
      toast.push('error', (err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const runRdi = async () => {
    if (!blobB64) return
    setBusy(true)
    setError('')
    try {
      const res = await api.shellcodeRdi({
        data_b64: blobB64,
        function_name: opts.functionName.trim() || 'StartW',
        arguments: '',
      })
      await setBlob(res.DataB64)
      toast.push('success', t('loaders.rdiDone', { size: res.Size }))
    } catch (err) {
      setError((err as Error).message)
      toast.push('error', (err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const runEncode = async () => {
    if (!blobB64) return
    setBusy(true)
    setError('')
    try {
      const res = await api.shellcodeEncode({
        data_b64: blobB64,
        encoder: opts.encoder,
        arch: opts.arch,
        iterations: opts.iterations,
        bad_chars_hex: badChars,
      })
      await setBlob(res.data_b64)
      toast.push('success', t('loaders.encodeDone', { encoder: res.encoder, size: res.size }))
    } catch (err) {
      setError((err as Error).message)
      toast.push('error', (err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const downloadBlob = () => {
    if (!blobB64) return
    triggerDownload(`${(sourceName || 'payload').replace(/\.[^.]+$/, '')}.bin`, base64ToBytes(blobB64))
  }

  const buildExe = async () => {
    if (!blobB64) {
      toast.push('error', t('loaders.needShellcode'))
      return
    }
    setBusy(true)
    setBusyMsg(t('loaders.building', { os: opts.os, arch: opts.arch }))
    setError('')
    try {
      const res = await api.loadersBuild({
        data_b64: blobB64,
        os: opts.os,
        arch: opts.arch,
        name: sourceName || 'payload',
        hide_console: opts.hideConsole,
        persistence: opts.persistence,
        persist_name: opts.persistName,
        xor_key: opts.xorKey.trim() || undefined,
        function_name: opts.functionName.trim() || 'StartW',
      })
      const bin = base64ToBytes(res.data_b64)
      triggerDownload(res.filename, bin)
      if (res.dll_data_b64 && res.dll_filename) {
        triggerDownload(res.dll_filename, base64ToBytes(res.dll_data_b64))
      }
      const hash = (await sha256Hex(bin)).slice(0, 16)
      toast.push(
        'success',
        t('loaders.wrapDownloaded', {
          name: res.filename,
          size: res.size,
          os: res.os,
          arch: res.arch,
          engine: res.engine || 'go',
          hash,
        }),
      )
      if (res.engine === 'mingw-c-dll' && res.dll_filename) {
        toast.push('success', t('loaders.wrapDownloadedDll', { name: res.dll_filename }))
      }
      setLastClean(res.clean || null)
      if (res.clean?.remaining && res.clean.remaining.length > 0) {
        toast.push('error', t('loaders.cleanRemaining', { count: res.clean.remaining.length }))
      } else if (res.clean?.replaced && res.clean.replaced.length > 0) {
        toast.push('success', t('loaders.cleanReplaced', { count: res.clean.replaced.length }))
      }
    } catch (err) {
      setError((err as Error).message)
      toast.push('error', (err as Error).message)
    } finally {
      setBusy(false)
      setBusyMsg('')
    }
  }

  const runFork = async (dryRun: boolean) => {
    setBusy(true)
    setBusyMsg(t('loaders.forkRunning'))
    setError('')
    setForkReport(null)
    try {
      const res = await api.forkRewrite({
        root: forkRoot.trim(),
        new_module: forkBranding ? forkModule.trim() : undefined,
        branding: forkBranding,
        proto: forkProto,
        generator: forkGenerator,
        dry_run: dryRun,
      })
      setForkReport(res)
      toast.push('success', dryRun ? t('loaders.forkDryDone') : t('loaders.forkApplyDone'))
    } catch (err) {
      setError((err as Error).message)
      toast.push('error', (err as Error).message)
    } finally {
      setBusy(false)
      setBusyMsg('')
    }
  }

  const startStageListener = async () => {
    if (!stageProfile) {
      toast.push('error', t('loaders.needProfile'))
      return
    }
    setBusy(true)
    setError('')
    try {
      const res = await api.stageListenerStart({
        url: stageURL,
        profile: stageProfile,
        aes_key: aesKey || undefined,
        aes_iv: aesKey ? aesIV : undefined,
        compress: compress || undefined,
      })
      setLastKeys({ aes: res.aes_key, iv: res.aes_iv, rc4: res.rc4_key, job: res.job_id })
      toast.push('success', t('loaders.stageStarted', { id: res.job_id, size: res.payload_size }))
    } catch (err) {
      setError((err as Error).message)
      toast.push('error', (err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const generateStage = async () => {
    if (!stageProfile) {
      toast.push('error', t('loaders.needProfile'))
      return
    }
    setBusy(true)
    setError('')
    try {
      const res = await api.stageGenerate({
        profile: stageProfile,
        aes_key: aesKey || undefined,
        aes_iv: aesKey ? aesIV : undefined,
        compress: compress || undefined,
        prepend_size: true,
        return_cipher: true,
      })
      setLastKeys({ aes: res.aes_key, iv: res.aes_iv, rc4: res.rc4_key })
      triggerDownload(res.filename || 'stage.bin', base64ToBytes(res.data_b64))
      toast.push('success', t('loaders.stageGenerated', { size: res.size, enc: res.encrypted }))
    } catch (err) {
      setError((err as Error).message)
      toast.push('error', (err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const persistChoices = persistOptions(opts.os)

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1 className="page-title">{t('loaders.title')}</h1>
          <p className="page-sub">{t('loaders.sub')}</p>
        </div>
        <div className="toolbar">
          <button type="button" className="btn" onClick={refresh} disabled={busy}>
            {t('common.refresh')}
          </button>
        </div>
      </header>

      <p className="form-hint">{t('loaders.whatIsThis')}</p>
      <p className="form-hint">{t('loaders.disclaimer')}</p>
      {error && <div className="error-banner">{error}</div>}

      <div className={blobB64 ? 'payload-bar' : 'payload-bar empty'}>
        {blobB64 ? (
          <>
            <span className="k">{t('loaders.size')}</span>
            <span className="v">{blobSize.toLocaleString()} B</span>
            <span className="k">SHA-256</span>
            <span className="v">{blobHash}</span>
            <span className="k">{t('loaders.target')}</span>
            <span className="v">
              {opts.os}/{opts.arch} → {outputName}
            </span>
            {busyMsg && <span className="v">{busyMsg}</span>}
          </>
        ) : (
          <span>{busyMsg || t('loaders.noBlob')}</span>
        )}
      </div>

      <div className="tabs" role="tablist">
        {(['wrap', 'tools', 'stage', 'fork'] as Tab[]).map((id) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={tab === id}
            className={`btn ${tab === id ? 'is-on' : ''}`}
            onClick={() => setTab(id)}
          >
            {t(`loaders.tab.${id}`)}
          </button>
        ))}
      </div>

      {tab === 'wrap' && (
        <div className="split">
          <section className="card">
            <h2 className="card-title">{t('loaders.step1')}</h2>
            <p className="muted">{t('loaders.step1Hint')}</p>
            <label className="field">
              <span>{t('loaders.pickBuild')}</span>
              <select
                value={sourceName}
                onChange={(e) => {
                  const name = e.target.value
                  setSourceName(name)
                  applyBuildMeta(builds.find((b) => b.Name === name))
                }}
              >
                <option value="">{t('loaders.selectBuild')}</option>
                {loaderBuilds.map((b) => (
                  <option key={b.Name} value={b.Name}>
                    {formatLabel(b)}
                  </option>
                ))}
              </select>
            </label>
            <div className="form-actions">
              <button type="button" className="btn primary" disabled={!sourceName || busy} onClick={loadBuild}>
                {t('loaders.loadBuild')}
              </button>
              <label className="btn">
                {t('loaders.upload')}
                <input type="file" hidden onChange={(e) => onUpload(e.target.files?.[0] || null)} />
              </label>
            </div>
            <p className="muted">
              {t('loaders.sourceHint')} <Link to="/implants">{t('nav.implants')}</Link>
            </p>
            {sharedSource && opts.os === 'windows' && <p className="warn-hint">{t('loaders.diskDllHint')}</p>}
            {sharedSource && opts.os !== 'windows' && <p className="muted">{t('loaders.rdiAuto')}</p>}
            {selectedC2s.length > 0 && (
              <div className="c2-cell">
                {selectedC2s.map((c) => (
                  <div key={c.URL}>
                    <span className="mono">{c.URL}</span> <C2JobStatus url={c.URL} jobs={jobs} />
                  </div>
                ))}
              </div>
            )}
            {missingC2.length > 0 && <p className="warn-hint">{t('loaders.c2Missing')}</p>}
            {loopbackC2 && <p className="warn-hint">{t('loaders.c2Loopback')}</p>}
            {selectedIsBeacon && <p className="warn-hint">{t('loaders.beaconWatch')}</p>}
          </section>

          <section className="card">
            <h2 className="card-title">{t('loaders.step2')}</h2>
            <p className="muted">{t('loaders.step2Hint')}</p>
            <div className="form-grid">
              <label className="field">
                <span>{t('loaders.os')}</span>
                <select
                  value={opts.os}
                  onChange={(e) => setOpts((o) => ({ ...o, os: e.target.value }))}
                >
                  <option value="windows">windows</option>
                  <option value="linux">linux</option>
                  <option value="darwin">darwin</option>
                </select>
              </label>
              <label className="field">
                <span>{t('loaders.arch')}</span>
                <select
                  value={opts.arch}
                  onChange={(e) => setOpts((o) => ({ ...o, arch: e.target.value }))}
                >
                  <option value="amd64">amd64</option>
                  <option value="386">386</option>
                  <option value="arm64">arm64</option>
                  <option value="arm">arm</option>
                </select>
              </label>
            </div>
            <div className="field check">
              <label>
                <input
                  type="checkbox"
                  checked={opts.hideConsole}
                  onChange={(e) => setOpts((o) => ({ ...o, hideConsole: e.target.checked }))}
                />
                {t('loaders.hideConsole')}
              </label>
            </div>
            <p className="muted">{t('loaders.hideConsoleHint')}</p>
            {opts.hideConsole && (
              <div className="form-actions">
                <button
                  type="button"
                  className="btn"
                  onClick={() => setOpts((o) => ({ ...o, hideConsole: false }))}
                >
                  {t('loaders.labConsoleBtn')}
                </button>
              </div>
            )}
            <p className="muted">{t('loaders.labConsole')}</p>
            <label className="field">
              <span>{t('loaders.persistTitle')}</span>
              <select
                value={opts.persistence}
                onChange={(e) => setOpts((o) => ({ ...o, persistence: e.target.value }))}
              >
                {persistChoices.map((p) => (
                  <option key={p.value} value={p.value}>
                    {t(`loaders.${p.key}`)}
                  </option>
                ))}
              </select>
            </label>
            <p className="muted">{t('loaders.persistHint')}</p>
            {opts.persistence !== 'off' && (
              <>
                <label className="field">
                  <span>{t('loaders.persistName')}</span>
                  <input
                    value={opts.persistName}
                    onChange={(e) => setOpts((o) => ({ ...o, persistName: e.target.value }))}
                    autoComplete="off"
                  />
                </label>
                <p className="warn-hint">{t('loaders.persistWarn')}</p>
                <p className="muted">
                  {t(
                    opts.persistence === 'all'
                      ? `loaders.cleanup.all_${opts.os}`
                      : `loaders.cleanup.${opts.persistence}`,
                    { name: opts.persistName },
                  )}
                </p>
              </>
            )}
            <label className="field">
              <span>{t('loaders.xorKey')}</span>
              <input
                value={opts.xorKey}
                onChange={(e) => setOpts((o) => ({ ...o, xorKey: e.target.value }))}
                placeholder={t('loaders.xorKeyPh')}
                autoComplete="off"
              />
            </label>
            <p className="muted">{t('loaders.xorUnique')}</p>
            <p className="muted">{t('loaders.wrapResult', { name: outputName })}</p>
            <div className="form-actions">
              <button type="button" className="btn" disabled={!blobB64} onClick={downloadBlob}>
                {t('loaders.download')}
              </button>
              <button type="button" className="btn primary" disabled={!blobB64 || busy} onClick={buildExe}>
                {busyMsg ? t('loaders.building', { os: opts.os, arch: opts.arch }) : t('loaders.downloadExeZip')}
              </button>
            </div>
            <p className="muted">{t('loaders.wrapCompileHint')}</p>
            <p className="muted">{t('loaders.runHint')}</p>
            <p className="muted">{t('loaders.keepAliveHint')}</p>
            <p className="muted">{t('loaders.nativeCHint')}</p>
            <p className="muted">{t('loaders.diskDllCopy')}</p>
            <p className="muted">{t('loaders.cleanHint')}</p>
            {lastClean && (lastClean.replaced?.length || lastClean.remaining?.length) ? (
              <div className="warn-hint">
                {lastClean.export ? <div>export {lastClean.export}</div> : null}
                {lastClean.replaced && lastClean.replaced.length > 0 ? (
                  <div>{t('loaders.cleanReplaced', { count: lastClean.replaced.length })}</div>
                ) : null}
                {lastClean.remaining && lastClean.remaining.length > 0 ? (
                  <div>
                    {t('loaders.cleanRemaining', { count: lastClean.remaining.length })}{' '}
                    <span className="mono">{lastClean.remaining.slice(0, 12).join(', ')}</span>
                  </div>
                ) : null}
              </div>
            ) : null}
            <p className="muted">{t('loaders.defenderHint')}</p>
          </section>
        </div>
      )}

      {tab === 'tools' && (
        <div className="split">
          <section className="card">
            <h2 className="card-title">{t('loaders.step1')}</h2>
            <p className="muted">{t('loaders.step1Hint')}</p>
            <label className="field">
              <span>{t('loaders.pickBuild')}</span>
              <select
                value={sourceName}
                onChange={(e) => {
                  const name = e.target.value
                  setSourceName(name)
                  applyBuildMeta(builds.find((b) => b.Name === name))
                }}
              >
                <option value="">{t('loaders.selectBuild')}</option>
                {loaderBuilds.map((b) => (
                  <option key={b.Name} value={b.Name}>
                    {formatLabel(b)}
                  </option>
                ))}
              </select>
            </label>
            <div className="form-actions">
              <button type="button" className="btn primary" disabled={!sourceName || busy} onClick={loadBuild}>
                {t('loaders.loadBuild')}
              </button>
              <label className="btn">
                {t('loaders.upload')}
                <input type="file" hidden onChange={(e) => onUpload(e.target.files?.[0] || null)} />
              </label>
            </div>
          </section>
          <section className="card">
            <h2 className="card-title">{t('loaders.transform')}</h2>
            <p className="muted">{t('loaders.toolsHint')}</p>
            <div className="field check">
              <label>
                <input type="checkbox" checked={doRdi} onChange={(e) => setDoRdi(e.target.checked)} />
                {t('loaders.rdi')}
              </label>
            </div>
            {doRdi && (
              <label className="field">
                <span>{t('loaders.rdiFn')}</span>
                <input
                  value={opts.functionName}
                  onChange={(e) => setOpts({ ...opts, functionName: e.target.value })}
                  placeholder="StartW"
                />
              </label>
            )}
            <div className="form-grid">
              <label className="field">
                <span>{t('loaders.encoder')}</span>
                <select value={opts.encoder} onChange={(e) => setOpts({ ...opts, encoder: e.target.value })}>
                  {encoderNames.map((n) => (
                    <option key={n} value={n}>
                      {n}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span>{t('loaders.arch')}</span>
                <input value={opts.arch} onChange={(e) => setOpts({ ...opts, arch: e.target.value })} />
              </label>
              <label className="field">
                <span>{t('loaders.iterations')}</span>
                <input
                  type="number"
                  min={1}
                  max={20}
                  value={opts.iterations}
                  onChange={(e) => setOpts({ ...opts, iterations: Number(e.target.value) || 1 })}
                />
              </label>
              <label className="field">
                <span>{t('loaders.badChars')}</span>
                <input value={badChars} onChange={(e) => setBadChars(e.target.value)} placeholder="00 0a 0d" />
              </label>
            </div>
            <div className="form-actions">
              <button type="button" className="btn" disabled={!blobB64 || !doRdi || busy} onClick={runRdi}>
                {t('loaders.runRdi')}
              </button>
              <button type="button" className="btn primary" disabled={!blobB64 || busy} onClick={runEncode}>
                {t('loaders.runEncode')}
              </button>
              <button type="button" className="btn" disabled={!blobB64} onClick={downloadBlob}>
                {t('loaders.download')}
              </button>
            </div>
          </section>
        </div>
      )}

      {tab === 'stage' && (
        <section className="card">
          <h2 className="card-title">{t('loaders.stageTitle')}</h2>
          <p className="muted">{t('loaders.stageHint')}</p>
          <div className="form-grid">
            <label className="field">
              <span>{t('loaders.profile')}</span>
              <select value={stageProfile} onChange={(e) => setStageProfile(e.target.value)}>
                <option value="">{t('loaders.selectProfile')}</option>
                {profiles.map((p) => (
                  <option key={p.Name} value={p.Name}>
                    {p.Name}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>{t('loaders.stageUrl')}</span>
              <input value={stageURL} onChange={(e) => setStageURL(e.target.value)} placeholder="tcp://0.0.0.0:8443" />
            </label>
            <label className="field">
              <span>{t('loaders.aesKey')}</span>
              <input
                value={aesKey}
                onChange={(e) => setAesKey(e.target.value)}
                placeholder={t('loaders.aesKeyPh')}
                autoComplete="off"
              />
            </label>
            <label className="field">
              <span>{t('loaders.aesIv')}</span>
              <input value={aesIV} onChange={(e) => setAesIV(e.target.value)} autoComplete="off" />
            </label>
            <label className="field">
              <span>{t('loaders.compress')}</span>
              <select value={compress} onChange={(e) => setCompress(e.target.value)}>
                <option value="">{t('loaders.compressNone')}</option>
                <option value="zlib">zlib</option>
                <option value="gzip">gzip</option>
                <option value="deflate">deflate</option>
              </select>
            </label>
          </div>
          <div className="form-actions">
            <button type="button" className="btn primary" disabled={busy} onClick={startStageListener}>
              {t('loaders.startListener')}
            </button>
            <button type="button" className="btn" disabled={busy} onClick={generateStage}>
              {t('loaders.downloadStage')}
            </button>
          </div>
          {lastKeys && (
            <div className="payload-bar">
              <strong>{t('loaders.keysOnce')}</strong>
              {lastKeys.job != null && <span className="v">job {lastKeys.job}</span>}
              {lastKeys.aes && (
                <span className="v">
                  AES {lastKeys.aes} / {lastKeys.iv || ''}
                </span>
              )}
              {lastKeys.rc4 && <span className="v">RC4 {lastKeys.rc4}</span>}
              <span className="k">{t('loaders.keysOnceHint')}</span>
            </div>
          )}
        </section>
      )}

      {tab === 'fork' && (
        <section className="card">
          <h2 className="card-title">{t('loaders.forkTitle')}</h2>
          <p className="muted">{t('loaders.forkHint')}</p>
          <p className="warn-hint">{t('loaders.forkWarn')}</p>
          <div className="form-grid">
            <label className="field span-all">
              <span>{t('loaders.forkRoot')}</span>
              <input
                value={forkRoot}
                onChange={(e) => setForkRoot(e.target.value)}
                placeholder="/home/operator/src/sliver"
                autoComplete="off"
              />
            </label>
            <label className="field span-all">
              <span>{t('loaders.forkModule')}</span>
              <input
                value={forkModule}
                onChange={(e) => setForkModule(e.target.value)}
                autoComplete="off"
                disabled={!forkBranding}
              />
            </label>
            <div className="field check">
              <label>
                <input
                  type="checkbox"
                  checked={forkBranding}
                  onChange={(e) => setForkBranding(e.target.checked)}
                />
                {t('loaders.forkBranding')}
              </label>
            </div>
            <div className="field check">
              <label>
                <input type="checkbox" checked={forkProto} onChange={(e) => setForkProto(e.target.checked)} />
                {t('loaders.forkProto')}
              </label>
            </div>
            <div className="field check">
              <label>
                <input
                  type="checkbox"
                  checked={forkGenerator}
                  onChange={(e) => setForkGenerator(e.target.checked)}
                />
                {t('loaders.forkGenerator')}
              </label>
            </div>
          </div>
          <p className="muted">{t('loaders.forkBrandingHint')}</p>
          <p className="muted">{t('loaders.forkProtoHint')}</p>
          <p className="muted">{t('loaders.forkGeneratorHint')}</p>
          <p className="muted">{t('loaders.forkRotate')}</p>
          <div className="form-actions">
            <button
              type="button"
              className="btn"
              disabled={busy || !forkRoot.trim() || (!forkBranding && !forkProto && !forkGenerator)}
              onClick={() => void runFork(true)}
            >
              {t('loaders.forkDryRun')}
            </button>
            <button
              type="button"
              className="btn primary"
              disabled={busy || !forkRoot.trim() || (!forkBranding && !forkProto && !forkGenerator)}
              onClick={() => void runFork(false)}
            >
              {t('loaders.forkApply')}
            </button>
          </div>
          {forkReport && (
            <div className="warn-hint">
              <div>{forkReport.note}</div>
              <div>
                files {forkReport.files ?? 0}
                {forkReport.dry_run ? ` (${t('loaders.forkDryRun')})` : ''}
                {forkReport.needs_ui_build ? ` · ${t('loaders.forkNeedsUI')}` : ''}
              </div>
              {forkReport.next?.map((n) => (
                <div key={n} className="mono">
                  {n}
                </div>
              ))}
              {forkReport.changed && forkReport.changed.length > 0 && (
                <div className="mono">{forkReport.changed.slice(0, 12).join(', ')}</div>
              )}
            </div>
          )}
        </section>
      )}
    </div>
  )
}
