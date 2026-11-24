import { describe, expect, it } from 'vitest'
import { isPrivilegedSession } from '../privilege'

describe('isPrivilegedSession', () => {
  it('treats uid 0 and SYSTEM as privileged', () => {
    expect(isPrivilegedSession({ UID: '0', Username: 'nobody' })).toBe(true)
    expect(isPrivilegedSession({ UID: 'S-1-5-18', Username: 'x' })).toBe(true)
    expect(isPrivilegedSession({ UID: '1000', Username: 'NT AUTHORITY\\SYSTEM' })).toBe(true)
    expect(isPrivilegedSession({ UID: '1000', Username: 'root' })).toBe(true)
  })

  it('treats standard users as unprivileged', () => {
    expect(isPrivilegedSession({ UID: '1000', Username: 'cup' })).toBe(false)
    expect(isPrivilegedSession({ UID: '', Username: '' })).toBe(false)
  })
})
