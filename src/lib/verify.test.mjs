// src/lib/verify.test.mjs
// C0 — 저장된 체인 해시 legacy text-hex 읽기 해석 (ADR-032)
// 실행: node --test src/lib/verify.test.mjs   (Node ≥ 22.18, 의존성 없음)

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { decodeStoredHash, verifyChainV2 } from './verify.ts'

/** 문자열의 각 글자를 ASCII 바이트로 보고 hex로 (legacy 행 재현용) */
function asciiHex(s) {
  let out = ''
  for (let i = 0; i < s.length; i++) out += s.charCodeAt(i).toString(16).padStart(2, '0')
  return out
}

const HASH = '0123456789abcdef'.repeat(4) // hex 64자
const INVALID = { hex: null, format: 'invalid' }

const canonical = hex => '\\x' + hex
const legacy = hex => '\\x' + asciiHex(hex)

// chain_hash = SHA256(UTF8(hex(prev_bytes || payload_bytes || uint32BE(seq) || utf8(ts))))
function chainHash(prevHex, payloadHex, seq, ts) {
  const seqBuf = Buffer.alloc(4)
  seqBuf.writeUInt32BE(seq)
  const combined = Buffer.concat([
    Buffer.from(prevHex, 'hex'), Buffer.from(payloadHex, 'hex'), seqBuf, Buffer.from(ts, 'utf8'),
  ])
  return createHash('sha256').update(combined.toString('hex'), 'utf8').digest('hex')
}

/** genesis 포함 3개 이벤트 체인 (해석된 hex 기준) */
function buildChain() {
  const types = ['genesis', 'capture', 'continuity']
  const rows = []
  let prev = '0'.repeat(64)
  for (let seq = 0; seq < 3; seq++) {
    const payload = createHash('sha256').update(`payload-${seq}`).digest('hex')
    const ts = `2026-11-13T00:00:0${seq}.000Z`
    const chain = chainHash(prev, payload, seq, ts)
    rows.push({ seq, event_type: types[seq], ts_utc: ts, payload_hash: payload, prev_hash: prev, chain_hash: chain })
    prev = chain
  }
  return rows
}

/** 해시 세 열을 지정한 저장 형식으로 */
function store(row, enc) {
  return { ...row, payload_hash: enc(row.payload_hash), prev_hash: enc(row.prev_hash), chain_hash: enc(row.chain_hash) }
}

test('#1 decode: \\x + hex 64자 (대문자 포함) → canonical, 소문자', () => {
  assert.deepEqual(decodeStoredHash('\\x' + HASH), { hex: HASH, format: 'canonical' })
  assert.deepEqual(decodeStoredHash('\\x' + HASH.toUpperCase()), { hex: HASH, format: 'canonical' })
})

test('#2 decode: \\x + ASCII hex 128자 → legacy_text_hex, 원래 hex 소문자', () => {
  const stored = '\\x' + asciiHex(HASH)
  assert.equal(stored.length, 2 + 128)
  assert.deepEqual(decodeStoredHash(stored), { hex: HASH, format: 'legacy_text_hex' })
  assert.deepEqual(decodeStoredHash('\\x' + asciiHex(HASH.toUpperCase())), { hex: HASH, format: 'legacy_text_hex' })
  assert.deepEqual(decodeStoredHash('\\x' + asciiHex('0'.repeat(64))), { hex: '0'.repeat(64), format: 'legacy_text_hex' })
})

test('#3 decode: invalid 경우 전부 → invalid, 예외 없음', () => {
  const cases = {
    'non-hex byte': '\\x' + asciiHex('g' + HASH.slice(1)),
    'binary 64 (ff×64)': '\\x' + 'ff'.repeat(64),
    '31 bytes': '\\x' + 'ab'.repeat(31),
    '33 bytes': '\\x' + 'ab'.repeat(33),
    '0 bytes': '\\x',
    'null': null,
    'undefined': undefined,
    'number': 42,
    'object': {},
    'no \\x': HASH,
    'odd length': '\\x' + HASH.slice(1),
    'non-hex chars (zz)': '\\x' + 'zz'.repeat(32),
    '0x prefix': '0x' + HASH,
  }
  for (const [name, value] of Object.entries(cases)) {
    let result
    assert.doesNotThrow(() => { result = decodeStoredHash(value) }, name)
    assert.deepEqual(result, INVALID, name)
  }
})

test('#4 V2: canonical 행만의 3개 이벤트 체인 → pass, legacy 0', async () => {
  const rows = buildChain().map(r => store(r, canonical))
  const r = await verifyChainV2(rows)
  assert.equal(r.status, 'pass', r.detail)
  assert.equal(r.legacyTextHexRows, 0)
  assert.equal(r.invalidRows, 0)
  assert.equal(r.summary.total_events, 3)
})

test('#5 V2: seq 1–2의 세 해시를 legacy 형식으로 저장 → pass, legacyTextHexRows 2', async () => {
  const rows = buildChain().map(r => store(r, r.seq >= 1 ? legacy : canonical))
  const r = await verifyChainV2(rows)
  assert.equal(r.status, 'pass', r.detail)
  assert.equal(r.legacyTextHexRows, 2)
  assert.equal(r.invalidRows, 0)
})

test('#6 V2: #5에서 legacy 행 chain_hash 글자 하나 변경 → fail', async () => {
  const base = buildChain()
  const tampered = base.map(r => ({ ...r }))
  const h = tampered[2].chain_hash
  tampered[2].chain_hash = (h[0] === 'a' ? 'b' : 'a') + h.slice(1) // 여전히 유효한 hex 글자
  const rows = tampered.map(r => store(r, r.seq >= 1 ? legacy : canonical))
  const r = await verifyChainV2(rows)
  assert.equal(r.status, 'fail')
  assert.equal(r.invalidRows, 0)
  assert.equal(r.legacyTextHexRows, 2)
  assert.match(r.detail, /chain_hash 불일치 — seq=2/)
})

test('#7 V2: 한 행의 content_hash가 invalid(33바이트) → fail, invalidRows 1', async () => {
  const rows = buildChain().map(r => ({ ...store(r, canonical), content_hash: canonical(HASH) }))
  rows[1].content_hash = '\\x' + 'ab'.repeat(33)
  const r = await verifyChainV2(rows)
  assert.equal(r.status, 'fail')
  assert.equal(r.invalidRows, 1)
  assert.equal(r.detail, '저장 형식을 해석할 수 없는 행 1개')
})

test('#8 V2: 이벤트 0개 → 기존과 같은 fail ("체인 이벤트 없음")', async () => {
  const r = await verifyChainV2([])
  assert.deepEqual(r, { status: 'fail', detail: '체인 이벤트 없음' })
})
