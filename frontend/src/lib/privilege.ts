export function isPrivilegedSession(s: { UID?: string; Username?: string }): boolean {
  const uid = (s.UID || '').trim()
  if (uid === '0' || uid === 'S-1-5-18') return true
  const u = (s.Username || '').toLowerCase()
  return (
    u === 'root' ||
    u === 'system' ||
    u === 'nt authority\\system' ||
    u.endsWith('\\system') ||
    u.endsWith('/root')
  )
}
