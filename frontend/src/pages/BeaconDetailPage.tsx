import { useCallback, useEffect, useRef, useState, type MouseEvent } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import type { Beacon, BeaconTask, Job } from '../lib/types'
import InlineEdit from '../components/InlineEdit'
import C2JobStatus from '../components/C2JobStatus'
import DataTable, { type Column } from '../components/common/DataTable'
import StatusBadge from '../components/common/StatusBadge'
import ConfirmDialog from '../components/common/ConfirmDialog'
import DetailDrawer from '../components/common/DetailDrawer'
import { useToast } from '../components/common/Toast'
import NotesPanel from '../components/session/NotesPanel'
import WasmTab from '../components/session/WasmTab'
import './pages.css'
import './session.css'

type TFunc = ReturnType<typeof useTranslation>['t']

function fmtTime(ts: string | number, t: TFunc): string {
  if (!ts) return '-'
  const num = typeof ts === 'number' ? ts * 1000 : new Date(ts).getTime()
  const d = new Date(num)
  if (Number.isNaN(d.getTime())) return String(ts)
  const now = Date.now()
  const diff = Math.round((now - d.getTime()) / 1000)
  if (diff < 60) return t('time.secondsAgo', { count: diff })
  if (diff < 3600) return t('time.minutesAgo', { count: Math.round(diff / 60) })
  if (diff < 86400) return t('time.hoursAgo', { count: Math.round(diff / 3600) })
  return t('time.daysAgo', { count: Math.round(diff / 86400) })
}

function taskTone(state: string): 'green' | 'red' | 'yellow' {
  if (state === 'completed') return 'green'
  if (state === 'failed') return 'red'
  return 'yellow'
}

function decodeResponse(b64?: string): string {
  if (!b64) return ''
  try {
    const bin = atob(b64)
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0))
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
  } catch {
    return b64
  }
}

function parseSeconds(raw: string): number | undefined {
  const trimmed = raw.trim()
  if (!trimmed) return undefined
  const n = Number(trimmed)
  if (!Number.isFinite(n)) return undefined
  return Math.round(n)
}

function secondsPrefill(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return ''
  if (n >= 1_000_000_000) return String(Math.round(n / 1_000_000_000))
  return String(Math.round(n))
}

export default function BeaconDetailPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { t } = useTranslation()
  const toast = useToast()
  const [beacon, setBeacon] = useState<Beacon | null>(null)
  const [error, setError] = useState('')
  const [tasks, setTasks] = useState<BeaconTask[]>([])
  const [selected, setSelected] = useState<BeaconTask | null>(null)
  const [content, setContent] = useState('')
  const [loadingContent, setLoadingContent] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [busy, setBusy] = useState(false)
  const [opening, setOpening] = useState(false)
  const [queueing, setQueueing] = useState(false)
  const [execPath, setExecPath] = useState('')
  const [execArgs, setExecArgs] = useState('')
  const [lsPath, setLsPath] = useState('.')
  const [jobs, setJobs] = useState<Job[]>([])
  const [openDelay, setOpenDelay] = useState('')
  const [openC2s, setOpenC2s] = useState('')
  const [reconReconnect, setReconReconnect] = useState('')
  const [reconInterval, setReconInterval] = useState('')
  const [reconJitter, setReconJitter] = useState('')
  const [reconC2, setReconC2] = useState('')
  const [reconBusy, setReconBusy] = useState(false)
  const reconPrefillId = useRef('')

  const openSession = async () => {
    if (!beacon) return
    setOpening(true)
    try {
      const opts: { delay?: number; c2s?: string[] } = {}
      const delay = parseSeconds(openDelay)
      if (delay !== undefined && delay > 0) opts.delay = delay
      const c2s = openC2s
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean)
      if (c2s.length) opts.c2s = c2s
      const res = await api.openSessionFromBeacon(
        beacon.ID,
        opts.delay !== undefined || opts.c2s ? opts : undefined,
      )
      if (res.async) {
        toast.push('success', t('beacons.sessionQueued', { name: beacon.Name }))
      } else {
        toast.push('success', t('beacons.sessionOpened'))
      }
      navigate('/sessions')
    } catch (e) {
      toast.push('error', `${t('common.failed')}: ${(e as Error).message}`)
    } finally {
      setOpening(false)
    }
  }

  const applyReconfigure = async () => {
    if (!beacon) return
    const opts: {
      reconnect_interval?: number
      beacon_interval?: number
      beacon_jitter?: number
      c2_uri?: string
    } = {}
    const reconnect = parseSeconds(reconReconnect)
    if (reconnect !== undefined) opts.reconnect_interval = reconnect
    const interval = parseSeconds(reconInterval)
    if (interval !== undefined) opts.beacon_interval = interval
    const jitter = parseSeconds(reconJitter)
    if (jitter !== undefined) opts.beacon_jitter = jitter
    const c2 = reconC2.trim()
    if (c2) opts.c2_uri = c2
    if (Object.keys(opts).length === 0) return
    setReconBusy(true)
    try {
      const result = await api.reconfigureBeacon(beacon.ID, opts)
      if (result.async) {
        toast.push('success', t('beacons.reconQueued', { name: beacon.Name }))
      } else {
        toast.push('success', t('beacons.reconDone', { name: beacon.Name }))
      }
    } catch (e) {
      toast.push('error', `${t('common.failed')}: ${(e as Error).message}`)
    } finally {
      setReconBusy(false)
    }
  }

  const load = useCallback(async () => {
    if (!id) return
    try {
      const b = await api.beacon(id)
      setBeacon(b)
      setError('')
    } catch (e) {
      setBeacon(null)
      setError(t('detail.notFound'))
    }
  }, [id, t])

  const loadTasks = useCallback(async () => {
    if (!id) return
    try {
      const d = await api.beaconTasks(id)
      setTasks((d.tasks || []).sort((a, b) => b.CreatedAt - a.CreatedAt))
    } catch (e) {
      setError((e as Error).message)
    }
  }, [id])

  useEffect(() => {
    load()
    const t1 = setInterval(load, 5000)
    return () => clearInterval(t1)
  }, [load])

  useEffect(() => {
    if (!beacon) return
    if (reconPrefillId.current === beacon.ID) return
    reconPrefillId.current = beacon.ID
    setReconInterval(secondsPrefill(beacon.Interval))
    setReconReconnect('')
    setReconJitter('')
    setReconC2('')
  }, [beacon])

  useEffect(() => {
    const loadJobs = () => {
      api
        .jobs()
        .then((d) => setJobs(d.jobs || []))
        .catch(() => {
          /* keep last jobs */
        })
    }
    loadJobs()
    const t = setInterval(loadJobs, 8000)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    loadTasks()
    const t2 = setInterval(loadTasks, 5000)
    return () => clearInterval(t2)
  }, [loadTasks])

  const rename = async (name: string) => {
    if (!beacon) return
    try {
      await api.renameBeacon(beacon.ID, name)
      setBeacon({ ...beacon, Name: name })
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const open = async (task: BeaconTask) => {
    setSelected(task)
    setLoadingContent(true)
    setContent('')
    try {
      const full = await api.beaconTaskContent(task.BeaconID, task.ID)
      setContent(decodeResponse(full.ResponseB64))
    } catch (e) {
      setContent(`${t('common.failed')}: ${(e as Error).message}`)
    } finally {
      setLoadingContent(false)
    }
  }

  const queue = async (fn: () => Promise<{ task_id?: string }>, fallback: string) => {
    if (!beacon) return
    setQueueing(true)
    try {
      const res = await fn()
      toast.push('success', t('beacons.taskQueued', { task: res.task_id?.slice(0, 8) || fallback }))
      await loadTasks()
    } catch (e) {
      toast.push('error', `${t('common.failed')}: ${(e as Error).message}`)
    } finally {
      setQueueing(false)
    }
  }

  const queueExec = () => {
    const path = execPath.trim()
    if (!path || !beacon) return
    const args = execArgs.trim() ? execArgs.trim().split(/\s+/) : []
    void queue(() => api.beaconExec(beacon.ID, path, args), path)
  }

  const cancelTask = async (task: BeaconTask, e: MouseEvent) => {
    e.stopPropagation()
    if (!beacon) return
    try {
      await api.cancelBeaconTask(beacon.ID, task.ID)
      toast.push('success', t('beacons.taskCanceled', { task: task.ID.slice(0, 8) }))
      await loadTasks()
    } catch (err) {
      toast.push('error', t('beacons.cancelFailed', { msg: (err as Error).message }))
    }
  }

  const remove = async () => {
    if (!beacon) return
    setBusy(true)
    try {
      await api.rmBeacon(beacon.ID)
      toast.push('success', t('beacons.removed', { name: beacon.Name }))
      navigate('/beacons')
    } catch (e) {
      toast.push('error', `${t('common.failed')}: ${(e as Error).message}`)
    } finally {
      setBusy(false)
    }
  }

  const columns: Column<BeaconTask>[] = [
    {
      key: 'State',
      label: t('tasks.thState'),
      sortable: true,
      render: (task) => <StatusBadge tone={taskTone(task.State)}>{task.State}</StatusBadge>,
    },
    {
      key: 'Description',
      label: t('tasks.thDescription'),
      sortable: true,
      render: (task) => <span className="mono task-desc">{task.Description}</span>,
    },
    {
      key: 'CreatedAt',
      label: t('tasks.thCreated'),
      sortable: true,
      sortValue: (task) => task.CreatedAt,
      render: (task) => fmtTime(task.CreatedAt, t),
    },
    {
      key: 'CompletedAt',
      label: t('tasks.thCompleted'),
      sortable: true,
      sortValue: (task) => task.CompletedAt || 0,
      render: (task) => fmtTime(task.CompletedAt, t),
    },
    {
      key: 'actions',
      label: '',
      render: (task) =>
        task.State === 'pending' ? (
          <button type="button" className="btn sm" onClick={(e) => void cancelTask(task, e)}>
            {t('beacons.cancelTask')}
          </button>
        ) : null,
    },
  ]

  return (
    <div className="page page-detail">
      {error && <div className="error-banner">{error}</div>}
      {beacon && (
        <>
          <div className="issue-header">
            <div className="issue-title-block">
              <div className="issue-title-row">
                <InlineEdit value={beacon.Name} onSave={rename} mono />
                <StatusBadge tone="blue">BEACON</StatusBadge>
              </div>
              <div className="page-sub">
                {beacon.Hostname} · {beacon.RemoteAddress} · {beacon.Transport}
              </div>
            </div>
            <div className="toolbar">
              <button type="button" className="btn" onClick={() => navigate('/beacons')}>
                {t('detail.back')}
              </button>
            </div>
          </div>

          <div className="issue-layout">
            <div className="issue-main">
              <div className="card">
                <div className="card-title">{t('beacons.reconfigureTitle')}</div>
                <div className="form-grid" style={{ marginBottom: 12 }}>
                  <div className="field">
                    <label>{t('beacons.reconInterval')}</label>
                    <input
                      type="number"
                      min={0}
                      value={reconReconnect}
                      onChange={(e) => setReconReconnect(e.target.value)}
                    />
                  </div>
                  <div className="field">
                    <label>{t('beacons.beaconInterval')}</label>
                    <input
                      type="number"
                      min={0}
                      value={reconInterval}
                      onChange={(e) => setReconInterval(e.target.value)}
                    />
                  </div>
                  <div className="field">
                    <label>{t('beacons.beaconJitter')}</label>
                    <input
                      type="number"
                      min={0}
                      value={reconJitter}
                      onChange={(e) => setReconJitter(e.target.value)}
                    />
                  </div>
                  <div className="field">
                    <label>{t('beacons.c2Uri')}</label>
                    <input value={reconC2} onChange={(e) => setReconC2(e.target.value)} />
                  </div>
                  <div className="field" style={{ justifyContent: 'flex-end' }}>
                    <button
                      type="button"
                      className="btn"
                      onClick={() => void applyReconfigure()}
                      disabled={
                        reconBusy ||
                        (!reconReconnect.trim() &&
                          !reconInterval.trim() &&
                          !reconJitter.trim() &&
                          !reconC2.trim())
                      }
                    >
                      {reconBusy ? t('common.loading') : t('beacons.reconApply')}
                    </button>
                  </div>
                </div>
              </div>
              <WasmTab id={beacon.ID} kind="beacon" />
              <div className="card task-queue">
                <div className="card-title">{t('beacons.tasking')}</div>
                <div className="form-hint" style={{ marginBottom: 12 }}>
                  {t('beacons.taskingHint')}
                </div>
                <div className="form-grid">
                  <div className="field">
                    <label>{t('beacons.execPath')}</label>
                    <input
                      value={execPath}
                      onChange={(e) => setExecPath(e.target.value)}
                      placeholder="/bin/whoami"
                    />
                  </div>
                  <div className="field">
                    <label>{t('beacons.execArgs')}</label>
                    <input value={execArgs} onChange={(e) => setExecArgs(e.target.value)} />
                  </div>
                  <div className="field" style={{ justifyContent: 'flex-end' }}>
                    <button type="button" className="btn" onClick={queueExec} disabled={queueing || !execPath.trim()}>
                      {t('beacons.queueExec')}
                    </button>
                  </div>
                  <div className="field">
                    <label>{t('beacons.lsPath')}</label>
                    <input value={lsPath} onChange={(e) => setLsPath(e.target.value)} />
                  </div>
                  <div className="field" style={{ justifyContent: 'flex-end' }}>
                    <button
                      type="button"
                      className="btn"
                      onClick={() => beacon && void queue(() => api.beaconLs(beacon.ID, lsPath.trim() || '.'), 'ls')}
                      disabled={queueing}
                    >
                      {t('beacons.queueLs')}
                    </button>
                  </div>
                  <div className="field" style={{ justifyContent: 'flex-end' }}>
                    <button
                      type="button"
                      className="btn"
                      onClick={() => beacon && void queue(() => api.beaconPs(beacon.ID), 'ps')}
                      disabled={queueing}
                    >
                      {t('beacons.queuePs')}
                    </button>
                  </div>
                  <div className="field" style={{ justifyContent: 'flex-end' }}>
                    <button
                      type="button"
                      className="btn"
                      onClick={() => beacon && void queue(() => api.beaconScreenshot(beacon.ID), 'screenshot')}
                      disabled={queueing}
                    >
                      {t('beacons.queueScreenshot')}
                    </button>
                  </div>
                </div>
              </div>
              <div className="card card-flush">
                <div className="card-title" style={{ padding: '12px 16px 0' }}>
                  {t('beacons.tasks')}
                </div>
                <DataTable
                  columns={columns}
                  rows={tasks}
                  rowKey={(task) => task.ID}
                  searchable
                  searchPlaceholder={t('tasks.search')}
                  searchText={(task) => `${task.Description} ${task.State}`}
                  empty={t('tasks.empty')}
                  onRowClick={open}
                  navigable
                />
              </div>
            </div>
            <aside className="issue-side">
              <div className="side-card">
                <div className="side-card-title">{t('detail.sidebar.properties')}</div>
                <div className="side-row">
                  <span className="side-label">ID</span>
                  <span className="side-value mono">{beacon.ID}</span>
                </div>
                <div className="side-row">
                  <span className="side-label">{t('detail.sidebar.hostname')}</span>
                  <span className="side-value">{beacon.Hostname}</span>
                </div>
                <div className="side-row">
                  <span className="side-label">{t('detail.sidebar.user')}</span>
                  <span className="side-value">{beacon.Username}</span>
                </div>
                <div className="side-row">
                  <span className="side-label">{t('detail.sidebar.os')}</span>
                  <span className="side-value">{beacon.OS}/{beacon.Arch}</span>
                </div>
                <div className="side-row">
                  <span className="side-label">{t('detail.sidebar.transport')}</span>
                  <span className="side-value">{beacon.Transport}</span>
                </div>
                <div className="side-row">
                  <span className="side-label">{t('detail.sidebar.remote')}</span>
                  <span className="side-value mono">{beacon.RemoteAddress}</span>
                </div>
                <div className="side-row">
                  <span className="side-label">{t('detail.sidebar.c2')}</span>
                  <span className="side-value c2-cell">
                    <span className="mono">{beacon.ActiveC2}</span>
                    <C2JobStatus url={beacon.ActiveC2} jobs={jobs} />
                  </span>
                </div>
                <div className="side-row">
                  <span className="side-label">{t('beacons.thLastCheckin')}</span>
                  <span className="side-value">{fmtTime(beacon.LastCheckin, t)}</span>
                </div>
                <div className="side-row">
                  <span className="side-label">{t('beacons.thNextCheckin')}</span>
                  <span className="side-value">{fmtTime(beacon.NextCheckin, t)}</span>
                </div>
                <div className="side-row">
                  <span className="side-label">{t('beacons.thInterval')}</span>
                  <span className="side-value mono">
                    {beacon.Interval}s / {beacon.Jitter}%
                  </span>
                </div>
              </div>
              <div className="side-card">
                <div className="field">
                  <label>{t('beacons.openDelay')}</label>
                  <input
                    type="number"
                    min={0}
                    value={openDelay}
                    onChange={(e) => setOpenDelay(e.target.value)}
                  />
                </div>
                <div className="field" style={{ marginTop: 8 }}>
                  <label>{t('beacons.openC2s')}</label>
                  <textarea rows={3} value={openC2s} onChange={(e) => setOpenC2s(e.target.value)} />
                </div>
                <div className="form-hint" style={{ marginTop: 8 }}>
                  {t('beacons.openC2sHint')}
                </div>
              </div>
              <NotesPanel uuid={beacon.UUID || beacon.ID} kind="beacon" />
              <div className="side-actions">
                <button type="button" className="btn" onClick={openSession} disabled={opening}>
                  {opening ? t('common.loading') : t('beacons.openSession')}
                </button>
                <button type="button" className="btn danger" onClick={() => setRemoving(true)}>
                  {t('beacons.remove')}
                </button>
              </div>
            </aside>
          </div>
        </>
      )}
      {!error && !beacon && <div className="empty">{t('common.loading')}</div>}
      <DetailDrawer
        open={!!selected}
        title={t('tasks.detail')}
        subtitle={selected ? `${beacon?.Name || ''} · ${selected.ID}` : ''}
        onClose={() => setSelected(null)}
      >
        {selected && (
          <div className="task-detail">
            <div className="kv">
              <div className="side-row">
                <span className="side-label">{t('tasks.thState')}</span>
                <StatusBadge tone={taskTone(selected.State)}>{selected.State}</StatusBadge>
              </div>
              <div className="side-row">
                <span className="side-label">{t('tasks.thCreated')}</span>
                <span className="side-value">{fmtTime(selected.CreatedAt, t)}</span>
              </div>
              <div className="side-row">
                <span className="side-label">{t('tasks.thCompleted')}</span>
                <span className="side-value">{fmtTime(selected.CompletedAt, t)}</span>
              </div>
            </div>
            <div className="task-content">
              <div className="task-content-header">
                <span>{t('tasks.content')}</span>
              </div>
              {loadingContent ? <pre>{t('common.loading')}</pre> : <pre>{content || t('tasks.none')}</pre>}
            </div>
          </div>
        )}
      </DetailDrawer>
      <ConfirmDialog
        open={removing}
        title={t('beacons.confirmRemove')}
        danger
        busy={busy}
        confirmLabel={t('beacons.remove')}
        onConfirm={remove}
        onCancel={() => setRemoving(false)}
      >
        <p>{beacon ? t('beacons.confirmRemoveBody', { name: beacon.Name }) : ''}</p>
      </ConfirmDialog>
    </div>
  )
}
