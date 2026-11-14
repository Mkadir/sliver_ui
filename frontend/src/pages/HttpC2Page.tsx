import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import type { HTTPC2Profile } from '../lib/types'
import { useToast } from '../components/common/Toast'
import './pages.css'

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

  const load = async () => {
    try {
      const data = await api.httpC2Profiles()
      setProfiles(data.profiles || [])
      setError('')
    } catch (e) {
      setError((e as Error).message)
    }
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
              <th />
            </tr>
          </thead>
          <tbody>
            {profiles.length === 0 ? (
              <tr>
                <td colSpan={4} style={{ color: 'var(--text-mute)' }}>
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
    </div>
  )
}
