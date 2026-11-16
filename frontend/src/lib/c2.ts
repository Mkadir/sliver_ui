export interface C2UrlParts {
  proto: string
  host: string
  port: string
}

// Splits a C2 URL like "mtls://1.2.3.4:8888" into its protocol, host and
// port. Mirrors how the backend assembles C2 URLs (see buildC2URL in
// backend/internal/sliver/implants.go).
export function parseC2Url(url: string, fallbackProto = 'mtls'): C2UrlParts {
  const sep = '://'
  const idx = url.indexOf(sep)
  if (idx === -1) {
    const [host, ...portParts] = url.split(':')
    return { proto: fallbackProto, host: host || '', port: portParts.join(':') }
  }
  const rawProto = url.slice(0, idx)
  const rest = url.slice(idx + sep.length)
  const [host, ...portParts] = rest.split(':')
  return { proto: rawProto || fallbackProto, host: host || '', port: portParts.join(':') }
}

const DEFAULT_C2_PORT: Record<string, string> = {
  https: '443',
  http: '80',
  mtls: '8888',
  dns: '53',
  wg: '53',
  wireguard: '53',
}

export function defaultC2Port(proto: string): string {
  return DEFAULT_C2_PORT[proto.toLowerCase()] || ''
}

/** True when the port field is still a protocol default (or the old mtls 8888 leftover). */
export function isUnsetC2Port(port: string, proto: string): boolean {
  const p = port.trim()
  if (!p) return true
  if (p === defaultC2Port(proto)) return true
  return p === '8888'
}

function jobNamesForProto(proto: string): string[] {
  switch (proto.toLowerCase()) {
    case 'https':
      return ['https', 'http']
    case 'http':
      return ['http', 'https']
    case 'wg':
    case 'wireguard':
      return ['wg', 'wireguard']
    default:
      return [proto.toLowerCase()]
  }
}

export interface C2JobLike {
  ID?: number
  Name: string
  Protocol?: string
  Port: number
}

/** Matching live listener job for an implant/session C2 URL (protocol + port). */
export function matchC2Job<T extends C2JobLike>(url: string, jobs: T[]): T | undefined {
  if (!url) return undefined
  const { proto, port } = parseC2Url(url)
  const wantPort = port || defaultC2Port(proto)
  const names = jobNamesForProto(proto)
  return jobs.find((j) => {
    const n = (j.Name || '').toLowerCase()
    const p = (j.Protocol || '').toLowerCase()
    const nameOk = names.includes(n) || names.includes(p)
    if (!nameOk) return false
    if (!wantPort) return true
    return String(j.Port) === String(wantPort)
  })
}
