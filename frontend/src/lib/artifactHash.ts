const HASH_KEY = 'sliverui-implant-hashes'

function readMap(): Record<string, string> {
  try {
    const raw = localStorage.getItem(HASH_KEY)
    if (!raw) return {}
    const parsed = JSON.parse(raw) as unknown
    if (!parsed || typeof parsed !== 'object') return {}
    return parsed as Record<string, string>
  } catch {
    return {}
  }
}

export function implantHashes(): Record<string, string> {
  return readMap()
}

export function implantHashFor(name: string): string | undefined {
  const h = readMap()[name]
  return h || undefined
}

/** Stores SHA-256 for a build name. Returns another name that already had this digest. */
export function rememberImplantHash(name: string, hash: string): string | undefined {
  if (!name || !hash) return undefined
  const map = readMap()
  if (map[name] === hash) return undefined
  let collision: string | undefined
  for (const [n, h] of Object.entries(map)) {
    if (h === hash && n !== name) {
      collision = n
      break
    }
  }
  map[name] = hash
  try {
    localStorage.setItem(HASH_KEY, JSON.stringify(map))
  } catch {
    /* quota */
  }
  return collision
}

export function shortHash(hash: string, n = 16): string {
  if (!hash) return ''
  return hash.slice(0, n)
}
