import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { GROUPED_NAV, ICONS } from '../lib/nav'
import { api } from '../lib/api'
import type { Beacon, Session } from '../lib/types'

interface PaletteItem {
  id: string
  group: string
  label: string
  hint?: string
  path: string
}

function matches(q: string, item: PaletteItem): boolean {
  if (!q) return true
  const hay = `${item.label} ${item.hint || ''} ${item.path} ${item.group}`.toLowerCase()
  return q.split(/\s+/).every((tok) => hay.includes(tok))
}

export default function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const [sessions, setSessions] = useState<Session[]>([])
  const [beacons, setBeacons] = useState<Beacon[]>([])
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!open) return
    setQuery('')
    setActive(0)
    const tmr = window.setTimeout(() => inputRef.current?.focus(), 0)
    void Promise.all([api.sessions(), api.beacons()])
      .then(([s, b]) => {
        setSessions(s.sessions || [])
        setBeacons(b.beacons || [])
      })
      .catch(() => {
        setSessions([])
        setBeacons([])
      })
    return () => window.clearTimeout(tmr)
  }, [open])

  const items = useMemo<PaletteItem[]>(() => {
    const pages: PaletteItem[] = GROUPED_NAV.flatMap((sec) =>
      sec.items.map((it) => ({
        id: `nav:${it.key}`,
        group: t('palette.pages'),
        label: t(`nav.${it.key}`),
        hint: it.path,
        path: it.path,
      })),
    )
    const actions: PaletteItem[] = [
      { id: 'act:generate', group: t('palette.actions'), label: t('palette.generate'), hint: '/implants', path: '/implants' },
      { id: 'act:listen', group: t('palette.actions'), label: t('palette.listen'), hint: '/listeners', path: '/listeners' },
      { id: 'act:loot', group: t('palette.actions'), label: t('palette.loot'), hint: '/loot', path: '/loot' },
      { id: 'act:armory', group: t('palette.actions'), label: t('palette.armory'), hint: '/armory', path: '/armory' },
    ]
    const sess: PaletteItem[] = sessions.map((s) => ({
      id: `sess:${s.ID}`,
      group: t('palette.sessions'),
      label: s.Name || s.Hostname || s.ID,
      hint: `${s.Username}@${s.Hostname} ${s.OS}/${s.Arch}`,
      path: `/sessions/${s.ID}`,
    }))
    const beac: PaletteItem[] = beacons.map((b) => ({
      id: `beac:${b.ID}`,
      group: t('palette.beacons'),
      label: b.Name || b.Hostname || b.ID,
      hint: `${b.Username}@${b.Hostname} ${b.OS}/${b.Arch}`,
      path: `/beacons/${b.ID}`,
    }))
    return [...actions, ...pages, ...sess, ...beac]
  }, [t, sessions, beacons])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return items.filter((it) => matches(q, it)).slice(0, 40)
  }, [items, query])

  useEffect(() => {
    setActive(0)
  }, [query])

  const go = (item: PaletteItem) => {
    navigate(item.path)
    onClose()
  }

  if (!open) return null

  const grouped = filtered.reduce<Record<string, PaletteItem[]>>((acc, it) => {
    ;(acc[it.group] ||= []).push(it)
    return acc
  }, {})

  const flat = filtered

  return (
    <div
      className="palette-overlay"
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div
        className="palette"
        role="dialog"
        aria-modal="true"
        aria-label={t('palette.title')}
        onKeyDown={(e) => {
          if (e.key === 'Escape') {
            e.preventDefault()
            onClose()
          } else if (e.key === 'ArrowDown') {
            e.preventDefault()
            setActive((i) => Math.min(i + 1, Math.max(flat.length - 1, 0)))
          } else if (e.key === 'ArrowUp') {
            e.preventDefault()
            setActive((i) => Math.max(i - 1, 0))
          } else if (e.key === 'Enter') {
            e.preventDefault()
            const item = flat[active]
            if (item) go(item)
          }
        }}
      >
        <div className="palette-search">
          <span className="nav-icon">{ICONS.search}</span>
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t('palette.placeholder')}
            aria-label={t('palette.title')}
          />
          <kbd>esc</kbd>
        </div>
        <div className="palette-list">
          {flat.length === 0 && <div className="palette-empty">{t('palette.empty')}</div>}
          {Object.entries(grouped).map(([group, groupItems]) => (
            <div key={group} className="palette-group">
              <div className="palette-group-title">{group}</div>
              {groupItems.map((it) => {
                const idx = flat.indexOf(it)
                return (
                  <button
                    type="button"
                    key={it.id}
                    className={`palette-item${idx === active ? ' active' : ''}`}
                    onMouseEnter={() => setActive(idx)}
                    onClick={() => go(it)}
                  >
                    <span className="palette-item-label">{it.label}</span>
                    {it.hint && <span className="palette-item-hint">{it.hint}</span>}
                  </button>
                )
              })}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
