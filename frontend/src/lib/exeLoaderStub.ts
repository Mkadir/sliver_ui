/** XOR helper shared with tests. Compile lives on the backend. */

export function xorPayload(data: Uint8Array, key: string): Uint8Array {
  if (!key) return data
  const out = new Uint8Array(data.length)
  const kb = new TextEncoder().encode(key)
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ kb[i % kb.length]
  return out
}
