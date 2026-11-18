import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import type { Job, Website } from '../lib/types'
import ConfirmDialog from '../components/common/ConfirmDialog'
import ContextMenu from '../components/common/ContextMenu'
import { useToast } from '../components/common/Toast'
import './pages.css'

export default function ListenersPage() {
  const [jobs, setJobs] = useState<Job[]>([])
  const [error, setError] = useState('')
  const [type, setType] = useState('mtls')
  const [addr, setAddr] = useState('0.0.0.0')
  const [port, setPort] = useState('8888')
  const [tls, setTls] = useState(false)
  const [domain, setDomain] = useState('')
  const [website, setWebsite] = useState('')
  const [websites, setWebsites] = useState<Website[]>([])
  const [acme, setAcme] = useState(false)
  const [enforceOtp, setEnforceOtp] = useState(false)
  const [longPollTimeout, setLongPollTimeout] = useState('0')
  const [longPollJitter, setLongPollJitter] = useState('0')
  const [starting, setStarting] = useState(false)
  const [stopping, setStopping] = useState<Job | null>(null)
  const [busy, setBusy] = useState(false)
  const [menu, setMenu] = useState<{ x: number; y: number; job: Job } | null>(null)
  const { t } = useTranslation()
  const toast = useToast()
  const isHttp = type === 'http' || type === 'https'

  const load = async () => {
    try {
      const data = await api.jobs()
      setJobs(data.jobs || [])
      setError('')
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const loadWebsites = async () => {
    try {
      const data = await api.websites()
      setWebsites(data.websites || [])
    } catch {
      setWebsites([])
    }
  }

  useEffect(() => {
    load()
    loadWebsites()
    const t = setInterval(load, 3000)
    return () => clearInterval(t)
  }, [])

  const start = async () => {
    setStarting(true)
    try {
      await api.startListener({
        type,
        addr,
        port: Number(port),
        tls: tls || type === 'https',
        domain: domain || undefined,
        website: website || undefined,
        acme: isHttp ? acme : undefined,
        enforce_otp: isHttp ? enforceOtp : undefined,
        long_poll_timeout: isHttp ? Number(longPollTimeout) || undefined : undefined,
        long_poll_jitter: isHttp ? Number(longPollJitter) || undefined : undefined,
      })
      toast.push('success', t('listeners.started'))
      load()
    } catch (e) {
      toast.push('error', `${t('common.failed')}: ${(e as Error).message}`)
    } finally {
      setStarting(false)
    }
  }

  const stop = async (j: Job) => {
    setBusy(true)
    try {
      await api.stopListener(j.ID)
      toast.push('success', t('listeners.stopped', { id: j.ID }))
      setStopping(null)
      load()
    } catch (e) {
      toast.push('error', `${t('common.failed')}: ${(e as Error).message}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="page-title">{t('listeners.title')}</div>
          <div className="page-sub">{t('listeners.sub', { count: jobs.length })}</div>
        </div>
        <div className="toolbar">
          <button type="button" className="btn" onClick={load}>
            {t('common.refresh')}
          </button>
        </div>
      </div>
      {error && <div className="error-banner">{error}</div>}

      <div className="card">
        <div className="card-title">{t('listeners.startTitle')}</div>
        <div className="form-grid">
          <div className="field">
            <label>{t('listeners.protocol')}</label>
            <select value={type} onChange={(e) => setType(e.target.value)}>
              <option value="mtls">mTLS</option>
              <option value="http">HTTP</option>
              <option value="https">HTTPS</option>
              <option value="dns">DNS</option>
              <option value="wireguard">WireGuard</option>
            </select>
          </div>
          <div className="field">
            <label>{t('listeners.address')}</label>
            <input value={addr} onChange={(e) => setAddr(e.target.value)} />
          </div>
          <div className="field">
            <label>{t('listeners.port')}</label>
            <input value={port} onChange={(e) => setPort(e.target.value)} />
          </div>
          <div className="field" style={{ justifyContent: 'flex-end' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <input type="checkbox" checked={tls} onChange={(e) => setTls(e.target.checked)} />
              {t('listeners.enableTls')}
            </label>
            <button type="button" className="btn primary" onClick={start} disabled={starting}>
              {starting ? t('listeners.starting') : t('listeners.start')}
            </button>
          </div>
          {isHttp && (
            <>
              <div className="field">
                <label>{t('listeners.domain')}</label>
                <input
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="cdn.example.com"
                />
              </div>
              <div className="field">
                <label>{t('listeners.website')}</label>
                <select value={website} onChange={(e) => setWebsite(e.target.value)}>
                  <option value="">{t('listeners.websiteNone')}</option>
                  {websites.map((w) => (
                    <option key={w.Name} value={w.Name}>
                      {w.Name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="field">
                <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <input type="checkbox" checked={acme} onChange={(e) => setAcme(e.target.checked)} />
                  {t('listeners.acme')}
                </label>
              </div>
              <div className="field">
                <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <input
                    type="checkbox"
                    checked={enforceOtp}
                    onChange={(e) => setEnforceOtp(e.target.checked)}
                  />
                  {t('listeners.enforceOtp')}
                </label>
              </div>
              <div className="field">
                <label>{t('listeners.longPollTimeout')}</label>
                <input
                  type="number"
                  value={longPollTimeout}
                  onChange={(e) => setLongPollTimeout(e.target.value)}
                />
              </div>
              <div className="field">
                <label>{t('listeners.longPollJitter')}</label>
                <input
                  type="number"
                  value={longPollJitter}
                  onChange={(e) => setLongPollJitter(e.target.value)}
                />
              </div>
            </>
          )}
        </div>
        {isHttp && (
          <div className="form-hint" style={{ marginTop: 8 }}>
            {t('listeners.httpHint')}
          </div>
        )}
      </div>

      <div className="card card-flush">
        <table className="data">
          <thead>
            <tr>
              <th>{t('listeners.thId')}</th>
              <th>{t('listeners.thName')}</th>
              <th>{t('listeners.thProtocol')}</th>
              <th>{t('listeners.thPort')}</th>
              <th>{t('listeners.thDomains')}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {jobs.length === 0 && (
              <tr>
                <td colSpan={6} className="empty">
                  {t('listeners.empty')}
                </td>
              </tr>
            )}
            {jobs.map((j) => (
              <tr
                key={j.ID}
                onContextMenu={(e) => {
                  e.preventDefault()
                  setMenu({ x: e.clientX, y: e.clientY, job: j })
                }}
              >
                <td className="mono">{j.ID}</td>
                <td className="mono">{j.Name}</td>
                <td>
                  <span className="badge blue">{j.Protocol}</span>
                </td>
                <td className="mono">{j.Port}</td>
                <td className="mono">{j.Domains?.join(', ') || '-'}</td>
                <td>
                  <button type="button" className="btn sm danger" onClick={() => setStopping(j)}>
                    {t('listeners.stop')}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {menu && (
        <ContextMenu
          x={menu.x}
          y={menu.y}
          onClose={() => setMenu(null)}
          items={[
            {
              label: t('listeners.stop'),
              danger: true,
              onSelect: () => setStopping(menu.job),
            },
          ]}
        />
      )}
      <ConfirmDialog
        open={!!stopping}
        title={t('jobs.confirmStop')}
        danger
        busy={busy}
        confirmLabel={t('listeners.stop')}
        onConfirm={() => stopping && stop(stopping)}
        onCancel={() => setStopping(null)}
      >
        <p>
          {stopping
            ? t('jobs.confirmStopBody', { name: stopping.Name || stopping.Protocol, id: stopping.ID })
            : ''}
        </p>
      </ConfirmDialog>
    </div>
  )
}
