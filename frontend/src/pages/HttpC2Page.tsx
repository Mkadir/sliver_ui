import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import type { HTTPC2Profile, TrafficEncoder, TrafficEncoderAddResult } from '../lib/types'
import { fingerprintHttpC2Doc } from '../lib/httpc2Fingerprint'
import { useToast } from '../components/common/Toast'
import './pages.css'

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

/** Client-side starting points — save to the Sliver server to use in generates. */
const TEMPLATES: Record<string, unknown> = {
  'ms-update': {
    Name: 'ms-update',
    ImplantConfig: {
      UserAgent: 'Microsoft-Delivery-Optimization/10.0',
      ChromeBaseVersion: 0,
      NonceQueryArgChars: 'abcdefghijklmnopqrstuvwxyz0123456789',
      NonceQueryLength: 8,
      NonceMode: 'Hex',
      MaxFileGen: 3,
      MinFileGen: 1,
      MaxPathGen: 3,
      MinPathGen: 1,
      MaxPathLength: 64,
      MinPathLength: 8,
      Extensions: ['.cab', '.exe', '.ps1'],
      PathSegments: [
        { IsFile: false, Value: 'v11' },
        { IsFile: false, Value: 'deliveryoptimization' },
        { IsFile: true, Value: 'files' },
      ],
      Headers: [
        { Method: '', Name: 'Accept', Value: '*/*', Probability: 100 },
        { Method: '', Name: 'Accept-Encoding', Value: 'gzip, deflate', Probability: 100 },
      ],
    },
    ServerConfig: {
      RandomVersionHeaders: true,
      Headers: [{ Method: '', Name: 'Content-Type', Value: 'application/octet-stream', Probability: 100 }],
      Cookies: [{ Name: 'do-session' }],
    },
  },
  'jquery-cdn': {
    Name: 'jquery-cdn',
    ImplantConfig: {
      UserAgent:
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
      ChromeBaseVersion: 122,
      NonceQueryArgChars: 'abcdef0123456789',
      NonceQueryLength: 6,
      NonceMode: 'Hex',
      MaxFileGen: 2,
      MinFileGen: 1,
      MaxPathGen: 2,
      MinPathGen: 1,
      MaxPathLength: 48,
      MinPathLength: 6,
      Extensions: ['.js', '.css', '.map'],
      PathSegments: [
        { IsFile: false, Value: 'ajax' },
        { IsFile: false, Value: 'libs' },
        { IsFile: false, Value: 'jquery' },
        { IsFile: true, Value: 'jquery.min' },
      ],
      Headers: [
        { Method: '', Name: 'Accept', Value: '*/*', Probability: 100 },
        { Method: '', Name: 'Accept-Language', Value: 'en-US,en;q=0.9', Probability: 100 },
      ],
    },
    ServerConfig: {
      RandomVersionHeaders: false,
      Headers: [
        { Method: '', Name: 'Content-Type', Value: 'application/javascript; charset=utf-8', Probability: 100 },
        { Method: '', Name: 'Cache-Control', Value: 'public, max-age=31536000', Probability: 100 },
      ],
      Cookies: [{ Name: 'csrftoken' }],
    },
  },
}

export default function HttpC2Page() {
  const { t } = useTranslation()
  const toast = useToast()
  const [profiles, setProfiles] = useState<HTTPC2Profile[]>([])
  const [selected, setSelected] = useState('')
  const [jsonText, setJsonText] = useState('')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const [encoders, setEncoders] = useState<TrafficEncoder[]>([])
  const [encoderName, setEncoderName] = useState('')
  const [encoderFile, setEncoderFile] = useState<File | null>(null)
  const [encoderFileKey, setEncoderFileKey] = useState(0)
  const [encoderSkipTests, setEncoderSkipTests] = useState(false)
  const [encoderBusy, setEncoderBusy] = useState(false)
  const [encoderResult, setEncoderResult] = useState<TrafficEncoderAddResult | null>(null)

  const loadEncoders = async () => {
    try {
      const data = await api.trafficEncoders()
      setEncoders(data.encoders || [])
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const load = async () => {
    try {
      const data = await api.httpC2Profiles()
      setProfiles(data.profiles || [])
      setError('')
    } catch (e) {
      setError((e as Error).message)
    }
    await loadEncoders()
  }

  useEffect(() => {
    load()
  }, [])

  const openProfile = async (name: string) => {
    setSelected(name)
    try {
      const p = await api.httpC2Profile(name)
      setJsonText(JSON.stringify(p.raw || p, null, 2))
      setError('')
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const applyTemplate = (key: string) => {
    const tpl = TEMPLATES[key]
    if (!tpl) return
    setSelected(key)
    setJsonText(JSON.stringify(tpl, null, 2))
  }

  const liveFp = useMemo(() => {
    const raw = jsonText.trim()
    if (!raw) return null
    try {
      return fingerprintHttpC2Doc(JSON.parse(raw) as unknown)
    } catch {
      return null
    }
  }, [jsonText])

  const save = async () => {
    setSaving(true)
    try {
      const config = JSON.parse(jsonText)
      if (!config.Name && selected) config.Name = selected
      const name = config.Name || selected
      const exists = profiles.some((p) => p.name === name)
      // Sliver: overwrite=false creates; overwrite=true updates an existing profile.
      try {
        await api.saveHttpC2Profile(config, exists)
      } catch (err) {
        if (!exists) throw err
        await api.saveHttpC2Profile(config, false)
      }
      toast.push('success', t('httpc2.saved', { name }))
      await load()
      if (name) setSelected(name)
    } catch (e) {
      toast.push('error', `${t('common.failed')}: ${(e as Error).message}`)
    } finally {
      setSaving(false)
    }
  }

  const addEncoder = async () => {
    const name = encoderName.trim()
    if (!name || !encoderFile) return
    setEncoderBusy(true)
    try {
      const wasmB64 = await fileToBase64(encoderFile)
      const result = await api.addTrafficEncoder(name, wasmB64, encoderSkipTests)
      setEncoderResult(result)
      toast.push('success', t('httpc2.encoderAdded', { name: result.name || name }))
      setEncoderName('')
      setEncoderFile(null)
      setEncoderFileKey((k) => k + 1)
      await loadEncoders()
    } catch (e) {
      toast.push('error', `${t('common.failed')}: ${(e as Error).message}`)
    } finally {
      setEncoderBusy(false)
    }
  }

  const removeEncoder = async (name: string) => {
    if (!window.confirm(t('httpc2.encoderConfirmRemove', { name }))) return
    try {
      await api.removeTrafficEncoder(name)
      toast.push('success', t('httpc2.encoderRemoved', { name }))
      await loadEncoders()
    } catch (e) {
      toast.push('error', `${t('common.failed')}: ${(e as Error).message}`)
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="page-title">{t('httpc2.title')}</div>
          <div className="page-sub">{t('httpc2.sub')}</div>
        </div>
        <div className="toolbar">
          <button type="button" className="btn" onClick={load}>
            {t('common.refresh')}
          </button>
          <button type="button" className="btn primary" onClick={save} disabled={saving || !jsonText}>
            {saving ? t('httpc2.saving') : t('httpc2.save')}
          </button>
        </div>
      </div>
      {error && <div className="error-banner">{error}</div>}

      <div className="card">
        <div className="card-title">{t('httpc2.templates')}</div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {Object.keys(TEMPLATES).map((key) => (
            <button type="button" key={key} className="btn sm" onClick={() => applyTemplate(key)}>
              {key}
            </button>
          ))}
        </div>
        <div className="form-hint" style={{ marginTop: 8 }}>
          {t('httpc2.templateHint')}
        </div>
      </div>

      <div className="card card-flush">
        <div className="card-title" style={{ padding: '12px 16px 0' }}>
          {t('httpc2.serverProfiles')}
        </div>
        <table className="data">
          <thead>
            <tr>
              <th>{t('httpc2.thName')}</th>
              <th>{t('httpc2.thUa')}</th>
              <th>{t('httpc2.thExt')}</th>
              <th>{t('httpc2.thFingerprint')}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {profiles.length === 0 ? (
              <tr>
                <td colSpan={5} style={{ color: 'var(--text-mute)' }}>
                  {t('httpc2.empty')}
                </td>
              </tr>
            ) : (
              profiles.map((p) => (
                <tr key={p.name}>
                  <td className="mono">{p.name}</td>
                  <td>{String(p.implant_config?.user_agent || '—')}</td>
                  <td className="mono">
                    {Array.isArray(p.implant_config?.extensions)
                      ? (p.implant_config?.extensions as string[]).join(', ')
                      : '—'}
                  </td>
                  <td title={(p.fingerprint?.reasons || []).join('; ')}>
                    {p.looks_default ? (
                      <span className="c2-job missing">{t('httpc2.looksDefault')}</span>
                    ) : (
                      <span className="c2-job live">{t('httpc2.looksCustom')}</span>
                    )}
                  </td>
                  <td>
                    <button type="button" className="btn sm" onClick={() => openProfile(p.name)}>
                      {t('httpc2.edit')}
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="card">
        <div className="card-title">
          {t('httpc2.editor')} {selected ? `— ${selected}` : ''}
        </div>
        {liveFp?.looks_default && (
          <div className="form-hint warn-hint">{t('httpc2.defaultCopy')}</div>
        )}
        {liveFp && liveFp.reasons.length > 0 && (
          <ul className="fp-reasons">
            {liveFp.reasons.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
        )}
        <textarea
          value={jsonText}
          onChange={(e) => setJsonText(e.target.value)}
          spellCheck={false}
          style={{
            width: '100%',
            minHeight: 360,
            fontFamily: 'var(--font-mono)',
            fontSize: 'var(--fs-sm)',
            background: 'var(--bg-deep)',
            color: 'var(--text)',
            border: '1px solid var(--border-strong)',
            borderRadius: 'var(--radius)',
            padding: 12,
          }}
          placeholder={t('httpc2.editorPlaceholder')}
        />
      </div>

      <div className="card">
        <div className="card-title">{t('httpc2.encodersTitle')}</div>
        <div className="form-hint" style={{ marginBottom: 12 }}>
          {t('httpc2.encodersSub')}
        </div>
        <div className="form-grid" style={{ marginBottom: 12 }}>
          <div className="field">
            <label>{t('httpc2.encoderName')}</label>
            <input value={encoderName} onChange={(e) => setEncoderName(e.target.value)} />
          </div>
          <div className="field">
            <label>{t('httpc2.encoderWasm')}</label>
            <input
              key={encoderFileKey}
              type="file"
              accept=".wasm,application/wasm"
              onChange={(e) => setEncoderFile(e.target.files?.[0] || null)}
            />
          </div>
          <div className="field check">
            <label>
              <input
                type="checkbox"
                checked={encoderSkipTests}
                onChange={(e) => setEncoderSkipTests(e.target.checked)}
              />
              {t('httpc2.encoderSkipTests')}
            </label>
          </div>
          <div className="field" style={{ justifyContent: 'flex-end' }}>
            <button
              type="button"
              className="btn primary"
              onClick={() => void addEncoder()}
              disabled={encoderBusy || !encoderName.trim() || !encoderFile}
            >
              {encoderBusy ? t('common.loading') : t('httpc2.encoderAdd')}
            </button>
          </div>
        </div>
        {encoderResult && (
          <>
            <div className="form-hint">
              {t('httpc2.encoderTests', {
                passed: encoderResult.passed
                  ? encoderResult.total_tests
                  : (encoderResult.tests || []).filter((x) => x.success).length,
                total: encoderResult.total_tests,
              })}
            </div>
            {(encoderResult.tests || []).length > 0 && (
              <ul className="fp-reasons">
                {(encoderResult.tests || []).map((test, i) => (
                  <li key={`${test.name}-${i}`}>
                    {test.name}: {test.success ? t('httpc2.encoderPassed') : t('httpc2.encoderFailed')}
                    {test.err ? ` — ${test.err}` : ''}
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
        <table className="data">
          <thead>
            <tr>
              <th>{t('httpc2.encoderName')}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {encoders.length === 0 ? (
              <tr>
                <td colSpan={2} style={{ color: 'var(--text-mute)' }}>
                  {t('common.empty')}
                </td>
              </tr>
            ) : (
              encoders.map((enc) => (
                <tr key={enc.name}>
                  <td className="mono">{enc.name}</td>
                  <td>
                    <button type="button" className="btn sm" onClick={() => void removeEncoder(enc.name)}>
                      {t('httpc2.encoderRemove')}
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
