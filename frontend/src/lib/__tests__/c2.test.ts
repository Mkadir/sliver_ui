import { describe, it, expect } from 'vitest'
import { parseC2Url, matchC2Job, defaultC2Port, isUnsetC2Port } from '../c2'

describe('parseC2Url', () => {
  it('splits a full C2 URL', () => {
    expect(parseC2Url('mtls://1.2.3.4:8888')).toEqual({ proto: 'mtls', host: '1.2.3.4', port: '8888' })
    expect(parseC2Url('https://example.com:8443')).toEqual({ proto: 'https', host: 'example.com', port: '8443' })
  })

  it('handles URLs without a port', () => {
    expect(parseC2Url('dns://example.com')).toEqual({ proto: 'dns', host: 'example.com', port: '' })
  })

  it('falls back to mtls when no protocol is present', () => {
    expect(parseC2Url('1.2.3.4:8888')).toEqual({ proto: 'mtls', host: '1.2.3.4', port: '8888' })
    expect(parseC2Url('')).toEqual({ proto: 'mtls', host: '', port: '' })
  })
})

describe('matchC2Job', () => {
  const jobs = [
    { ID: 1, Name: 'https', Protocol: 'tcp', Port: 443 },
    { ID: 2, Name: 'mtls', Protocol: 'tcp', Port: 8888 },
  ]

  it('matches https C2 to an https listener on 443', () => {
    const j = matchC2Job('https://127.0.0.1:443', jobs)
    expect(j?.ID).toBe(1)
  })

  it('matches mtls C2 to the mtls job', () => {
    const j = matchC2Job('mtls://127.0.0.1:8888', jobs)
    expect(j?.ID).toBe(2)
  })

  it('returns undefined when no live job shares protocol+port', () => {
    expect(matchC2Job('https://127.0.0.1:8443', jobs)).toBeUndefined()
  })
})

describe('isUnsetC2Port', () => {
  it('treats protocol defaults and leftover 8888 as unset', () => {
    expect(defaultC2Port('https')).toBe('443')
    expect(isUnsetC2Port('443', 'https')).toBe(true)
    expect(isUnsetC2Port('8888', 'https')).toBe(true)
    expect(isUnsetC2Port('8443', 'https')).toBe(false)
    expect(isUnsetC2Port('8888', 'mtls')).toBe(true)
  })
})
