type TFunc = (key: string, opts?: { count: number }) => string

/** Format an RFC3339 (or unix-seconds) timestamp as a relative string. */
export function fmtRelativeTime(ts: string | number | undefined | null, t: TFunc): string {
  if (ts === undefined || ts === null || ts === '') return '-'
  const ms = typeof ts === 'number' ? (ts < 1e12 ? ts * 1000 : ts) : new Date(ts).getTime()
  if (Number.isNaN(ms)) return String(ts)
  const diff = Math.round((Date.now() - ms) / 1000)
  if (diff <= -86400) return t('time.daysIn', { count: Math.round(-diff / 86400) })
  if (diff <= -3600) return t('time.hoursIn', { count: Math.round(-diff / 3600) })
  if (diff <= -60) return t('time.minutesIn', { count: Math.round(-diff / 60) })
  if (diff < 0) return t('time.secondsIn', { count: Math.max(1, -diff) })
  if (diff < 10) return t('time.justNow')
  if (diff < 60) return t('time.secondsAgo', { count: diff })
  if (diff < 3600) return t('time.minutesAgo', { count: Math.round(diff / 60) })
  if (diff < 86400) return t('time.hoursAgo', { count: Math.round(diff / 3600) })
  return t('time.daysAgo', { count: Math.round(diff / 86400) })
}
