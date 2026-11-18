import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../../lib/api'
import type { RportFwdListener } from '../../lib/types'

export default function RportfwdTab({ sessionId, activeC2 }: { sessionId: string; activeC2?: string }) {
  const { t } = useTranslation()
  const [listeners, setListeners] = useState<RportFwdListener[]>([])
  const [bindHost, setBindHost] = useState('0.0.0.0')
  const [bindPort, setBindPort] = useState('8080')
  const [forwardHost, setForwardHost] = useState('127.0.0.1')
  const [forwardPort, setForwardPort] = useState('22')
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const dns = (activeC2 || '').toLowerCase().startsWith('dns://')

  const load = useCallback(async () => {
    setError('')
    try {
      const d = await api.rportfwdList(sessionId)
      setListeners(d.listeners || [])
    } catch (e) {
      setError((e as Error).message)
    }
  }, [sessionId])

  useEffect(() => {
    load()
  }, [load])

  const add = async () => {
    setError('')
    setMessage('')
    try {
      const res = await api.rportfwdStart(sessionId, {
        bind_host: bindHost,
        bind_port: Number(bindPort) || 0,
        forward_host: forwardHost,
        forward_port: Number(forwardPort) || 0,
      })
      setMessage(res.warning ? res.warning : t('rportfwd.added'))
      load()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const stop = async (id: number) => {
    setError('')
    try {
      await api.rportfwdStop(sessionId, id)
      setMessage(t('rportfwd.stopped'))
      load()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  return (
    <div className="card">
      <div className="card-title">{t('rportfwd.title')}</div>
      <p className="page-sub" style={{ marginBottom: 12 }}>
        {t('rportfwd.hint')}
      </p>
      {dns && <p className="form-hint warn-hint">{t('rportfwd.dnsWarn')}</p>}
      <div className="pf-form">
        <div className="field">
          <label>{t('rportfwd.bind')}</label>
          <input value={bindHost} onChange={(e) => setBindHost(e.target.value)} />
        </div>
        <div className="field">
          <label>{t('rportfwd.bindPort')}</label>
          <input type="number" value={bindPort} onChange={(e) => setBindPort(e.target.value)} />
        </div>
        <div className="field">
          <label>{t('rportfwd.forward')}</label>
          <input value={forwardHost} onChange={(e) => setForwardHost(e.target.value)} />
        </div>
        <div className="field">
          <label>{t('rportfwd.forwardPort')}</label>
          <input type="number" value={forwardPort} onChange={(e) => setForwardPort(e.target.value)} />
        </div>
        <div className="field" style={{ justifyContent: 'flex-end' }}>
          <button type="button" className="btn primary" onClick={add}>
            {t('rportfwd.add')}
          </button>
        </div>
      </div>
      {error && <div className="error-banner">{error}</div>}
      {message && (
        <div className="error-banner" style={{ borderColor: 'var(--green)', color: 'var(--green)', background: 'var(--success-bg)' }}>
          {message}
        </div>
      )}
      <table className="data">
        <thead>
          <tr>
            <th>{t('rportfwd.id')}</th>
            <th>{t('rportfwd.bindAddr')}</th>
            <th>{t('rportfwd.forwardAddr')}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {listeners.length === 0 && (
            <tr>
              <td colSpan={4} className="empty">
                {t('rportfwd.empty')}
              </td>
            </tr>
          )}
          {listeners.map((l) => (
            <tr key={l.ID}>
              <td className="mono">{l.ID}</td>
              <td className="mono">{l.BindAddress || `${l.BindPort}`}</td>
              <td className="mono">{l.ForwardAddress || `${l.ForwardPort}`}</td>
              <td>
                <button type="button" className="btn sm danger" onClick={() => stop(l.ID)}>
                  {t('rportfwd.stop')}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
