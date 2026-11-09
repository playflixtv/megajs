import test from 'ava'
import crypto from 'crypto'

import { AES, MAC } from '../lib/crypto/index.mjs'

// The original per-16-byte MAC (one ECB call per block). The batched MAC.update must stay
// byte-identical to it: a different MAC fails every download's integrity check.
function referenceMac (key, nonce, chunks) {
  const ecb = crypto.createCipheriv('aes-128-ecb', key, Buffer.alloc(0))
  let increment = 131072
  let posNext = increment
  let pos = 0
  const macs = []
  let mac = Buffer.concat([nonce, nonce])
  for (const buffer of chunks) {
    for (let i = 0; i < buffer.length; i += 16) {
      for (let j = 0; j < 16; j++) mac[j] ^= buffer[i + j]
      mac = ecb.update(mac)
      pos += 16
      if (pos >= posNext) {
        macs.push(Buffer.from(mac))
        mac = Buffer.concat([nonce, nonce])
        if (increment < 1048576) increment += 131072
        posNext += increment
      }
    }
  }
  macs.push(mac)
  let m = Buffer.alloc(16, 0)
  for (const item of macs) {
    for (let j = 0; j < 16; j++) m[j] ^= item[j]
    m = ecb.update(m)
  }
  const out = Buffer.allocUnsafe(8)
  out.writeInt32BE(m.readInt32BE(0) ^ m.readInt32BE(4), 0)
  out.writeInt32BE(m.readInt32BE(8) ^ m.readInt32BE(12), 4)
  return out
}

const sizes = [0, 1, 15, 16, 17, 131071, 131072, 131073, 131072 * 3 + 7, 3 * 1048576 + 5, 9 * 1048576 + 7]

for (const size of sizes) {
  test(`MAC.update batched equals the per-block MAC (${size} bytes, unaligned 16-byte-multiple chunks)`, t => {
    const key = crypto.randomBytes(16)
    const nonce = crypto.randomBytes(8)
    const data = crypto.randomBytes(size)
    // Feed 16-byte-aligned chunks of varying sizes (as chunkSizeSafe(16) does), the tail last.
    const chunks = []
    for (let off = 0, step = 16 * 997; off < size; off += step, step = step * 2 + 16 * 3) {
      chunks.push(data.subarray(off, Math.min(off + step, size)))
    }
    const mac = new MAC(new AES(key), Buffer.concat([nonce, Buffer.alloc(8)]))
    for (const chunk of chunks) mac.update(chunk)
    t.is(mac.condense().toString('hex'), referenceMac(key, nonce, chunks).toString('hex'))
  })
}
