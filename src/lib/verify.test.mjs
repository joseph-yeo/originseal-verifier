// src/lib/verify.test.mjs
// C0 — 저장된 체인 해시 legacy text-hex 읽기 해석 (ADR-032)
// C1 — getAttestation 응답 해석·클라이언트 V3 판정 (#10~#18)
// 실행: node --test src/lib/verify.test.mjs   (Node ≥ 22.18, 의존성 없음)

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { decodeStoredHash, verifyChainV2, decodeAttestationHead, evaluateAttestation } from './verify.ts'

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

// ─── C1: getAttestation 응답 해석 (발주서 §0-5의 운영 응답) ─────
const R1 = '0x0000000000000000000000000000000000000000000000000000000000000020443ecb9d74810da711b86cc960bff5f5de37872cf584e3dd38113699b79551a8c1c417819add3be7d9658b1f05674b7db7f65dc1fb5ff77e2e0cc70b19300719000000000000000000000000000000000000000000000000000000006af71afe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ccf3f16dc6899f0b7455798e4987ef06c7cb90640000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000001005d442385ff615b3a9f0aea9ef42cf441577bd921aefab532b5f8800a1052dcf70000000000000000000000000000000053e9f31742d74e718b69cbc88f33b653000000000000000000000000ccf3f16dc6899f0b7455798e4987ef06c7cb9064000000000000000000000000000000000000000000000000000000006af71ae00000000000000000000000000000000000000000000000000000000000000000b84449f0c3bdfe0cad6bf46ed2c1def132e977c6d1699685b944450f156fa13700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004'
const R0 = '0x' + '0'.repeat(62) + '20' + '0'.repeat(64 * 9) + '0'.repeat(61) + '140' + '0'.repeat(64)
const UID = '0x443ecb9d74810da711b86cc960bff5f5de37872cf584e3dd38113699b79551a8'
const AR = '5d442385ff615b3a9f0aea9ef42cf441577bd921aefab532b5f8800a1052dcf7'
const CHAIN = 'Polygon PoS'

test('#10 decodeAttestationHead: R1 → uid·time·데이터 첫 칸', () => {
  assert.deepEqual(decodeAttestationHead(R1), { uid: UID.slice(2), time: 1794579198, dataFirstWord: AR })
})

test('#11 decodeAttestationHead: R0(없는 UID) → uid 전부 0, time 0, dataFirstWord null', () => {
  assert.equal(R0.length, 2 + 64 * 12)
  assert.deepEqual(decodeAttestationHead(R0), { uid: '0'.repeat(64), time: 0, dataFirstWord: null })
})

test('#12 decodeAttestationHead: 해석할 수 없는 입력 → null, 예외 없음', () => {
  const offset40 = '0x' + '0'.repeat(62) + '40' + R1.slice(66)
  for (const input of ['0x', '0x' + '0'.repeat(64 * 12), '0x' + '0'.repeat(64 * 3), offset40, null, 12345, 'not-hex', '0xzz' + R1.slice(4)]) {
    assert.equal(decodeAttestationHead(input), null, String(input).slice(0, 20))
  }
})

test('#13 evaluateAttestation: R1 + 맞는 UID + 맞는 anchor_record → pass, 시각', () => {
  assert.deepEqual(evaluateAttestation(R1, UID, AR, CHAIN), {
    status: 'pass',
    detail: '온체인 기록 일치 (Polygon PoS)',
    attestationTime: '2026-11-13T14:13:18.000Z',
  })
})

test('#14 evaluateAttestation: UID 표기만 다름 + anchor_record 한 글자 다름 → fail, 시각 없음', () => {
  const badAr = AR.slice(0, -1) + (AR.endsWith('7') ? '8' : '7')
  for (const uid of [UID.toUpperCase().replace('0X', '0x'), UID.slice(2), UID.slice(2).toUpperCase()]) {
    assert.deepEqual(evaluateAttestation(R1, uid, badAr, CHAIN), {
      status: 'fail', detail: '온체인 기록 불일치 (anchor_record)',
    })
  }
})

test('#15 evaluateAttestation: R0 + 아무 UID → fail 미존재', () => {
  for (const uid of [UID, '0x01', '0x' + '0'.repeat(64)]) {
    assert.deepEqual(evaluateAttestation(R0, uid, AR, CHAIN), { status: 'fail', detail: '온체인 어테스테이션 미존재' })
  }
})

test('#16 evaluateAttestation: R1 + 다른 UID → fail 미존재', () => {
  const other = '0x' + 'ab'.repeat(32)
  assert.deepEqual(evaluateAttestation(R1, other, AR, CHAIN), { status: 'fail', detail: '온체인 어테스테이션 미존재' })
})

test('#17 evaluateAttestation: anchor_record 없음 / 63자 → pass 대조 안 함, 시각 없음', () => {
  for (const ar of [undefined, null, '', AR.slice(1)]) {
    assert.deepEqual(evaluateAttestation(R1, UID, ar, CHAIN), {
      status: 'pass', detail: '온체인 기록 존재 · 대조 안 함',
    })
  }
})

test('#18 evaluateAttestation: 해석 불가 입력 → error, 예외 없음', () => {
  for (const input of ['0x', null, undefined, 42, '0x1234', {}]) {
    assert.deepEqual(evaluateAttestation(input, UID, AR, CHAIN), { status: 'error', detail: '온체인 응답 해석 불가' })
  }
})
