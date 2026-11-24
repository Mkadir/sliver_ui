const KEY = 'sliverui.files.recents.v1'
const MAX = 8

export type FileRecent = { path: string; at: number }

function readAll(): Record<string, FileRecent[]> {
  try {
    const raw = localStorage.getItem(KEY)
    if (!raw) return {}
    const parsed = JSON.parse(raw) as Record<string, FileRecent[]>
    return parsed && typeof parsed === 'object' ? parsed : {}
  } catch {
    return {}
  }
}

function writeAll(all: Record<string, FileRecent[]>) {
  try {
    localStorage.setItem(KEY, JSON.stringify(all))
  } catch {
    /* quota */
  }
}

export function loadFileRecents(hostKey: string): FileRecent[] {
  if (!hostKey) return []
  const list = readAll()[hostKey] || []
  return [...list].sort((a, b) => b.at - a.at)
}

export function rememberFileRecent(hostKey: string, path: string): FileRecent[] {
  if (!hostKey || !path) return loadFileRecents(hostKey)
  const all = readAll()
  const next = (all[hostKey] || []).filter((r) => r.path !== path)
  next.unshift({ path, at: Date.now() })
  all[hostKey] = next.slice(0, MAX)
  writeAll(all)
  return all[hostKey]
}

export function clearFileRecents(hostKey: string) {
  if (!hostKey) return
  const all = readAll()
  delete all[hostKey]
  writeAll(all)
}
