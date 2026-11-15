import { describe, it, expect } from 'vitest'
import { analyzeHTTPC2Fingerprint, fingerprintHttpC2Doc } from '../httpc2Fingerprint'

describe('analyzeHTTPC2Fingerprint', () => {
  it('flags classic default extensions + nonce 1', () => {
    const fp = analyzeHTTPC2Fingerprint('default', ['.woff', '.php', '.png', '.js'], 1, '', [
      'JSESSIONID',
      'rememberMe',
    ])
    expect(fp.looks_default).toBe(true)
    expect(fp.reasons.length).toBeGreaterThan(2)
  })

  it('flags 1.7 default js/empty/php', () => {
    const fp = analyzeHTTPC2Fingerprint('default', ['js', '', 'php'], 1, '', [])
    expect(fp.looks_default).toBe(true)
  })

  it('passes ms-update template', () => {
    const fp = analyzeHTTPC2Fingerprint(
      'ms-update',
      ['.cab', '.exe', '.ps1'],
      8,
      'Microsoft-Delivery-Optimization/10.0',
      ['do-session'],
    )
    expect(fp.looks_default).toBe(false)
  })
})

describe('fingerprintHttpC2Doc', () => {
  it('reads protobuf-style JSON', () => {
    const fp = fingerprintHttpC2Doc({
      Name: 'default',
      ImplantConfig: { Extensions: ['js', '', 'php'], NonceQueryLength: 1, UserAgent: '' },
      ServerConfig: { Cookies: [{ Name: 'JSESSIONID' }, { Name: 'rememberMe' }] },
    })
    expect(fp.looks_default).toBe(true)
  })
})
