export interface HTTPC2Fingerprint {
  looks_default: boolean
  reasons: string[]
}

const DEFAULT_COOKIES = ['jsessionid', 'rememberme']

function normalizeExt(s: string): string {
  return s.trim().toLowerCase().replace(/^\./, '')
}

function extSet(exts: string[] | undefined): Set<string> {
  const out = new Set<string>()
  for (const e of exts || []) out.add(normalizeExt(e))
  return out
}

export function analyzeHTTPC2Fingerprint(
  name: string,
  extensions: string[] | undefined,
  nonce: number | undefined,
  userAgent: string | undefined,
  cookies: string[] | undefined,
): HTTPC2Fingerprint {
  const reasons: string[] = []
  const set = extSet(extensions)
  const has = (x: string) => set.has(x)
  const n = nonce ?? 0

  if (name.trim().toLowerCase() === 'default') reasons.push('profile name is default')
  if (n === 1) reasons.push('nonce query length is 1')
  if (has('woff') && has('php') && has('png')) {
    reasons.push('extensions still include .woff, .php, and .png')
  }
  if (has('php') && has('js') && has('')) {
    reasons.push('extensions still include .js, empty, and .php (1.7 default)')
  }
  if (!(userAgent || '').trim()) {
    reasons.push('user-agent is empty (server fills the Sliver default)')
  }
  let cookieHits = 0
  for (const c of cookies || []) {
    const cl = c.trim().toLowerCase()
    if (DEFAULT_COOKIES.includes(cl)) cookieHits++
  }
  if (cookieHits >= 2) reasons.push('cookies still include JSESSIONID and rememberMe')

  let looks = false
  if (has('woff') && has('php') && has('png') && n === 1) looks = true
  if (n === 1 && has('php') && has('js')) looks = true
  if (name.trim().toLowerCase() === 'default' && n === 1) looks = true
  return { looks_default: looks, reasons }
}

type Loose = Record<string, unknown>

function asRecord(v: unknown): Loose | undefined {
  if (v && typeof v === 'object' && !Array.isArray(v)) return v as Loose
  return undefined
}

function strList(v: unknown): string[] {
  if (!Array.isArray(v)) return []
  return v.map((x) => {
    if (typeof x === 'string') return x
    if (x && typeof x === 'object' && 'Name' in (x as Loose)) return String((x as Loose).Name || '')
    if (x && typeof x === 'object' && 'name' in (x as Loose)) return String((x as Loose).name || '')
    return ''
  }).filter(Boolean)
}

/** Fingerprint a raw HTTP C2 JSON document (editor or API `raw`). */
export function fingerprintHttpC2Doc(doc: unknown): HTTPC2Fingerprint {
  const root = asRecord(doc) || {}
  const implant = asRecord(root.ImplantConfig) || asRecord(root.implant_config) || asRecord(root.implantConfig)
  const server = asRecord(root.ServerConfig) || asRecord(root.server_config) || asRecord(root.serverConfig)
  const name = String(root.Name || root.name || '')
  const exts = strList(implant?.Extensions ?? implant?.extensions)
  const nonce = Number(implant?.NonceQueryLength ?? implant?.nonce_query_length ?? 0)
  const ua = String(implant?.UserAgent ?? implant?.user_agent ?? '')
  const cookies = strList(server?.Cookies ?? server?.cookies)
  return analyzeHTTPC2Fingerprint(name, exts, nonce, ua, cookies)
}
