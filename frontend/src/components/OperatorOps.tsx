import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import type { OperatorAuditEntry, OperatorReaction, OperatorReactionHit } from '../lib/types'

export default function OperatorOps() {
  const { t } = useTranslation()
  const [reactions, setReactions] = useState<OperatorReaction[]>([])
  const [events, setEvents] = useState<string[]>([])
  const [allowlist, setAllowlist] = useState<string[]>([])
  const [hint, setHint] = useState('')
  const [eventType, setEventType] = useState('session-connected')
  const [commands, setCommands] = useState('whoami')
  const [audit, setAudit] = useState<OperatorAuditEntry[]>([])
  const [auditHint, setAuditHint] = useState('')
  const [log, setLog] = useState<OperatorReactionHit[]>([])
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      const [r, a, l] = await Promise.all([api.operatorReactions(), api.operatorAudit(), api.operatorReactionLog()])
      setReactions(r.reactions || [])
      setEvents(r.events || [])
      setAllowlist(r.allowlist || [])
      setHint(r.hint || '')
      if (r.events?.[0]) {
        setEventType((cur) => (r.events.includes(cur) ? cur : r.events[0]))
      }
      setAudit(a.entries || [])
      setAuditHint(a.hint || '')
      setLog(l.entries || [])
    } catch (e) {
      setError((e as Error).message)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const add = async () => {
    setError('')
    try {
      await api.addOperatorReaction(
        eventType,
        commands
          .split('\n')
          .map((c) => c.trim())
          .filter(Boolean),
      )
      setCommands('whoami')
      load()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const remove = async (id: number) => {
    try {
      await api.removeOperatorReaction(id)
      load()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  return (
    <>
      <div className="card">
        <div className="card-title">{t('settings.reactionsTitle')}</div>
        <p className="page-sub">{hint || t('operator.reactionsHint')}</p>
        <p className="form-hint">
          {t('operator.allowlist')}: {allowlist.join(', ')}
        </p>
        <div className="pf-form">
          <div className="field">
            <label>{t('operator.event')}</label>
            <select value={eventType} onChange={(e) => setEventType(e.target.value)}>
              {events.map((ev) => (
                <option key={ev} value={ev}>
                  {ev}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label>{t('operator.commands')}</label>
            <textarea value={commands} onChange={(e) => setCommands(e.target.value)} rows={3} />
          </div>
          <div className="field" style={{ justifyContent: 'flex-end' }}>
            <button type="button" className="btn primary" onClick={add}>
              {t('operator.addReaction')}
            </button>
          </div>
        </div>
        {error && <div className="error-banner">{error}</div>}
        {reactions.length === 0 ? (
          <div className="empty">{t('operator.emptyReactions')}</div>
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th>ID</th>
                <th>{t('operator.event')}</th>
                <th>{t('operator.commands')}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {reactions.map((r) => (
                <tr key={r.id}>
                  <td className="mono">{r.id}</td>
                  <td className="mono">{r.event_type}</td>
                  <td className="mono">{(r.commands || []).join(', ')}</td>
                  <td>
                    <button type="button" className="btn sm danger" onClick={() => remove(r.id)}>
                      {t('operator.remove')}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {log.length > 0 && (
          <>
            <div className="card-title" style={{ marginTop: 16 }}>
              {t('operator.reactionLog')}
            </div>
            <ul>
              {log.slice(0, 8).map((h, i) => (
                <li key={`${h.time}-${i}`} className="form-hint">
                  {h.skipped
                    ? t('operator.reactionSkip')
                    : t('operator.reactionRan', { command: h.command, target: h.target || '—' })}
                  : {h.result}
                </li>
              ))}
            </ul>
          </>
        )}
      </div>

      <div className="card">
        <div className="card-title">{t('settings.auditTitle')}</div>
        <p className="page-sub">{auditHint || t('operator.auditHint')}</p>
        {audit.length === 0 ? (
          <div className="empty">{t('operator.auditEmpty')}</div>
        ) : (
          <table className="data audit-table">
            <thead>
              <tr>
                <th>{t('operator.time')}</th>
                <th>{t('operator.user')}</th>
                <th>{t('operator.sliverOperator')}</th>
                <th>{t('operator.action')}</th>
                <th>HTTP</th>
              </tr>
            </thead>
            <tbody>
              {audit.slice(0, 40).map((e, i) => (
                <tr key={`${e.time}-${i}`}>
                  <td className="mono">{e.time}</td>
                  <td>{e.user}</td>
                  <td>{e.operator || '—'}</td>
                  <td className="mono">{e.action}</td>
                  <td className="mono">{e.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}
