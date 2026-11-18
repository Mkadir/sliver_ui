import { describe, expect, it } from 'vitest'
import { xorPayload } from '../exeLoaderStub'
import { zipStore } from '../zip'

describe('zipStore', () => {
  it('builds a zip with local + central headers', () => {
    const data = new TextEncoder().encode('hello')
    const z = zipStore([{ name: 'a.txt', data }])
    // local header signature
    expect(z[0]).toBe(0x50)
    expect(z[1]).toBe(0x4b)
    expect(z[2]).toBe(0x03)
    expect(z[3]).toBe(0x04)
    // end of central directory signature somewhere near the end
    const view = new DataView(z.buffer, z.byteOffset, z.byteLength)
    let found = false
    for (let i = z.length - 22; i >= 0; i--) {
      if (view.getUint32(i, true) === 0x06054b50) {
        found = true
        break
      }
    }
    expect(found).toBe(true)
    expect(z.length).toBeGreaterThan(data.length + 30)
  })
})

describe('xorPayload', () => {
  it('round-trips with the same key', () => {
    const src = new Uint8Array([1, 2, 3, 4, 255])
    const enc = xorPayload(src, 'ab')
    expect(enc).not.toEqual(src)
    expect(xorPayload(enc, 'ab')).toEqual(src)
  })
})
