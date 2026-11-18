import { describe, expect, it } from 'vitest'
import { fmtRelativeTime } from '../time'

const t = (key: string, opts?: { count: number }) => `${key}:${opts?.count ?? 0}`

describe('fmtRelativeTime', () => {
  it('renders empty as dash', () => {
    expect(fmtRelativeTime('', t)).toBe('-')
    expect(fmtRelativeTime(undefined, t)).toBe('-')
  })

  it('renders future next-checkin as in N seconds', () => {
    const ts = new Date(Date.now() + 45_000).toISOString()
    expect(fmtRelativeTime(ts, t)).toBe('time.secondsIn:45')
  })

  it('renders recent past as just now', () => {
    const ts = new Date(Date.now() - 3_000).toISOString()
    expect(fmtRelativeTime(ts, t)).toBe('time.justNow:0')
  })
})
