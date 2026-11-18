import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../../lib/api'
import type { OperatorLock, OperatorNote } from '../../lib/types'

function parseTags(raw: string): string[] {
  return raw
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

export default function NotesPanel({
  uuid,
  kind,
  sessionId,
}: {
  uuid: string
  kind: 'session' | 'beacon' | 'host'
  sessionId?: string
}) {
  const { t } = useTranslation()
  const [note, setNote] = useState<OperatorNote | null>(null)
  const [tags, setTags] = useState('')
  const [comment, setComment] = useState('')
  const [campaign, setCampaign] = useState('')
  const [lock, setLock] = useState<OperatorLock | null>(null)
  const [held, setHeld] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    if (!uuid) return
    try {
      const n = await api.operatorNote(uuid)
      setNote(n)
      setTags((n.tags || []).join(', '))
      setComment(n.comment || '')
      setCampaign(n.campaign || '')
    } catch (e) {
      setError((e as Error).message)
    }
    if (sessionId) {
      try {
        const l = await api.operatorLock(sessionId)
        setHeld(l.held)
        setLock(l.held ? l.lock : null)
      } catch {
        /* lock is local-only */
      }
    }
  }, [uuid, sessionId])

  useEffect(() => {
    load()
  }, [load])

  const save = async () => {
    setBusy(true)
    setError('')
    setMessage('')
    try {
      const n = await api.putOperatorNote(uuid, {
        kind,
        tags: parseTags(tags),
        comment,
        campaign,
      })
      setNote(n)
      setMessage(t('operator.saved'))
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const takeLock = async () => {
    if (!sessionId) return
    setError('')
    try {
      const res = await api.takeOperatorLock(sessionId)
      setLock(res.lock)
      setHeld(true)
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const releaseLock = async () => {
    if (!sessionId) return
    setError('')
    try {
      await api.releaseOperatorLock(sessionId)
      setLock(null)
      setHeld(false)
    } catch (e) {
      setError((e as Error).message)
    }
  }

  return (
    <div className="side-card">
      <div className="side-card-title">{t('operator.notes')}</div>
      {sessionId && (
        <div style={{ marginBottom: 10 }}>
          {held && lock ? (
            <div className="op-lock-banner">
              <span>{t('operator.lockedBy', { user: lock.user || lock.operator || 'local' })}</span>
              <button type="button" className="btn sm" onClick={releaseLock}>
                {t('operator.unlock')}
              </button>
            </div>
          ) : (
            <button type="button" className="btn sm" onClick={takeLock}>
              {t('operator.takeLock')}
            </button>
          )}
          <p className="form-hint">{t('operator.lockHint')}</p>
        </div>
      )}
      <div className="field">
        <label>{t('operator.tags')}</label>
        <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder={t('operator.tagsPlaceholder')} />
      </div>
      <div className="field">
        <label>{t('operator.campaign')}</label>
        <input value={campaign} onChange={(e) => setCampaign(e.target.value)} />
      </div>
      <div className="field">
        <label>{t('operator.comment')}</label>
        <textarea value={comment} onChange={(e) => setComment(e.target.value)} rows={3} />
      </div>
      <button type="button" className="btn" onClick={save} disabled={busy || !uuid}>
        {t('operator.save')}
      </button>
      {note?.updated_at && <p className="form-hint">{note.updated_at}</p>}
      {message && <p className="form-hint">{message}</p>}
      {error && <div className="error-banner">{error}</div>}
    </div>
  )
}
