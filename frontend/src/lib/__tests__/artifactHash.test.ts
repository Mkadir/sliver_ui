import { describe, it, expect, beforeEach } from 'vitest'
import { rememberImplantHash, implantHashFor, shortHash } from '../artifactHash'

describe('rememberImplantHash', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('stores a hash and detects a collision with a different name', () => {
    expect(rememberImplantHash('a', 'abc')).toBeUndefined()
    expect(implantHashFor('a')).toBe('abc')
    expect(rememberImplantHash('b', 'abc')).toBe('a')
    expect(rememberImplantHash('a', 'abc')).toBeUndefined()
  })

  it('shortens a digest', () => {
    expect(shortHash('0123456789abcdefxxxx', 16)).toBe('0123456789abcdef')
  })
})
