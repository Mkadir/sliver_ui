import { beforeEach, describe, expect, it } from 'vitest'
import { clearFileRecents, loadFileRecents, rememberFileRecent } from '../filesRecents'

describe('filesRecents', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('stores recents per host uuid and caps at 8', () => {
    rememberFileRecent('host-a', '/tmp')
    rememberFileRecent('host-a', '/var')
    rememberFileRecent('host-b', '/home')
    expect(loadFileRecents('host-a').map((r) => r.path)).toEqual(['/var', '/tmp'])
    expect(loadFileRecents('host-b').map((r) => r.path)).toEqual(['/home'])
    for (let i = 0; i < 10; i++) rememberFileRecent('host-a', `/p${i}`)
    expect(loadFileRecents('host-a')).toHaveLength(8)
    clearFileRecents('host-a')
    expect(loadFileRecents('host-a')).toEqual([])
  })
})
