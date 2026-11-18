import { useMemo } from 'react'
import type { PivotGraphEntry, Session } from '../../lib/types'
import { isPrivilegedSession } from '../../lib/privilege'

function transportColor(t: string): string {
  const x = (t || '').toLowerCase()
  if (x.includes('https')) return '#38bdf8'
  if (x.includes('http')) return '#818cf8'
  if (x.includes('mtls')) return '#a78bfa'
  if (x.includes('dns')) return '#fbbf24'
  if (x.includes('wg') || x.includes('wireguard')) return '#34d399'
  if (x.includes('named') || x.includes('pipe') || x.includes('tcp')) return '#fb923c'
  return '#71717a'
}

function sessionsAsForest(sessions: Session[]): PivotGraphEntry[] {
  return sessions.map((s) => ({
    PeerID: 0,
    Name: s.Name,
    SessionID: s.ID,
    Hostname: s.Hostname,
    Username: s.Username,
    OS: s.OS,
    Transport: s.Transport,
    RemoteAddress: s.RemoteAddress,
    Children: [],
  }))
}

function Node({
  entry,
  sessionsById,
  onSelect,
}: {
  entry: PivotGraphEntry
  sessionsById: Map<string, Session>
  onSelect: (sessionId: string) => void
}) {
  const live = sessionsById.get(entry.SessionID)
  const priv = isPrivilegedSession({ UID: live?.UID, Username: live?.Username || entry.Username })
  const color = transportColor(entry.Transport)
  return (
    <li className="pivot-node">
      <button
        type="button"
        className={`pivot-card ${priv ? 'privileged' : ''}`}
        style={{ borderLeftColor: color }}
        onClick={() => entry.SessionID && onSelect(entry.SessionID)}
        disabled={!entry.SessionID}
      >
        <span className="pivot-name mono">{entry.Name || entry.Hostname || entry.SessionID || 'peer'}</span>
        <span className="pivot-meta">
          {entry.Username}
          {entry.Username && entry.Hostname ? '@' : ''}
          {entry.Hostname}
        </span>
        <span className="pivot-meta mono">
          {entry.OS} · {entry.Transport || '—'} · {entry.RemoteAddress}
        </span>
      </button>
      {entry.Children?.length > 0 && (
        <ul className="pivot-children" style={{ borderLeftColor: color }}>
          {entry.Children.map((ch, i) => (
            <Node
              key={`${ch.SessionID || ch.PeerID}-${i}`}
              entry={ch}
              sessionsById={sessionsById}
              onSelect={onSelect}
            />
          ))}
        </ul>
      )}
    </li>
  )
}

export default function PivotGraphView({
  graph,
  sessions,
  onSelect,
}: {
  graph: PivotGraphEntry[]
  sessions: Session[]
  onSelect: (sessionId: string) => void
}) {
  const sessionsById = useMemo(() => new Map(sessions.map((s) => [s.ID, s])), [sessions])
  const roots = useMemo(() => {
    if (graph.length > 0) return graph
    return sessionsAsForest(sessions)
  }, [graph, sessions])

  if (roots.length === 0) return null

  return (
    <div className="pivot-graph">
      <div className="pivot-legend">
        {[
          ['mtls', 'mtls'],
          ['https', 'https'],
          ['http', 'http'],
          ['dns', 'dns'],
          ['wg', 'wg'],
          ['tcp', 'tcp/named pipe'],
        ].map(([key, label]) => (
          <span key={key} className="pivot-legend-item">
            <i style={{ background: transportColor(key) }} />
            {label}
          </span>
        ))}
      </div>
      <ul className="pivot-forest">
        {roots.map((e, i) => (
          <Node key={`${e.SessionID || e.PeerID}-${i}`} entry={e} sessionsById={sessionsById} onSelect={onSelect} />
        ))}
      </ul>
    </div>
  )
}
