// ─── OriginSeal Client-Side Verification Utilities ──────────
// Sprint 7: 브라우저에서 독립 검증 수행 (서버를 신뢰하지 않아도 됨)
// Sprint 9-2: 다중 체인 지원 — chain_id 기반으로 RPC/EAS/EASScan 동적 라우팅
// ADR-018: SHA256(UTF8(hexString)) 공식 준수
// ADR-021: 클라이언트=온체인 독립 검증
// ADR-022: fetch + JSON-RPC eth_call만 사용 (ethers.js 번들 금지)
// ADR-032 / C0: 저장된 체인 해시(bytea)는 읽을 때만 해석한다 (저장 행은 고치지 않음)
//   서버 originseal-app _shared/stored-hash.ts (A3) 와 같은 규칙. 입력은 PostgREST bytea 문자열(`\x` + hex).
//   1. 문자열이 아니거나 `\x`로 시작하지 않으면 → invalid
//   2. 본문이 짝수 길이의 [0-9a-fA-F]* 가 아니면 → invalid
//   3. 디코드한 바이트 수가 32 → canonical. 해시 = 본문 소문자
//      64 이고 모든 바이트가 ASCII 0-9 a-f A-F (0x30-39, 0x61-66, 0x41-46) → legacy_text_hex.
//         해시 = 그 64바이트를 문자열로 읽어 소문자로
//      그 밖 → invalid
//   출력: { hex: 소문자 64자 | null, format }
//   행 분류 (서버 decodeStoredChainRows 와 같음): payload_hash·prev_hash·chain_hash, 값이 있으면 content_hash.
//   하나라도 invalid → invalid 행, 아니고 하나라도 legacy → legacy 행. invalid 행이 있으면 V2 실패.
//   원인: A3 이전 session-sync가 bytea에 `\x` 없이 hex 글자를 넣어 64바이트로 저장됨 (진단 F19).
//   이 파일은 import가 없어야 한다 (verify.test.mjs가 Node로 직접 불러온다).

export interface ChainConfig {
  rpc: string
  eas: string
  name: string
  easscanBase: string
}

export const CHAIN_CONFIG: Record<number, ChainConfig> = {
  11155111: {
    rpc: 'https://ethereum-sepolia-rpc.publicnode.com',
    eas: '0xC2679fBD37d54388Ce493F1DB75320D236e1815e',
    name: 'Ethereum Sepolia',
    easscanBase: 'https://sepolia.easscan.org/attestation/view',
  },
  137: {
    rpc: process.env.NEXT_PUBLIC_POLYGON_RPC_URL
      ?? 'https://polygon-bor-rpc.publicnode.com',
    eas: '0x5E634ef5355f45A855d02D66eCD687b1502AF790',
    name: 'Polygon PoS',
    easscanBase: 'https://polygon.easscan.org/attestation/view',
  },
}

export function getChainConfig(chainId: number | null | undefined): ChainConfig | null {
  if (chainId === null || chainId === undefined) return CHAIN_CONFIG[11155111]
  return CHAIN_CONFIG[chainId] ?? null
}

export function easscanUrl(
  chainId: number | null | undefined,
  easUid: string | null | undefined
): string | null {
  if (!easUid) return null
  const cfg = getChainConfig(chainId)
  return cfg ? `${cfg.easscanBase}/${easUid}` : null
}

// ─── Types ──────────────────────────────────────────────────
export interface VerifyResult {
  status: 'pass' | 'fail' | 'pending' | 'error' | 'skip' | 'na'
  detail: string
  easscan_url?: string
}

export interface V3Result extends VerifyResult {
  /** 온체인 어테스테이션의 time (ISO, UTC). UID와 anchor_record가 모두 일치할 때만 채운다 (C1 D1) */
  attestationTime?: string
}

export interface V2Result extends VerifyResult {
  summary?: {
    total_events: number
    captures: number
    continuity_records: number
    gaps: number
    blanks: number
    started_at: string | null
    ended_at: string | null
  }
  /** invalid가 없고 해시 열 중 하나라도 legacy_text_hex인 행 수 (ADR-032 읽기 해석) */
  legacyTextHexRows?: number
  /** 해시 열 중 하나라도 해석할 수 없는 행 수 */
  invalidRows?: number
}

export interface ChainEvent {
  seq: number
  event_type: string
  ts_utc: string
  ts_utc_raw?: string | null
  payload_hash: string
  prev_hash: string
  chain_hash: string
  [key: string]: unknown
}

// ─── Hex / Byte Utilities ───────────────────────────────────
export function normalizeHex(val: unknown): string {
  if (!val || typeof val !== 'string') return ''
  return val.replace(/^(0x|\\\\x|\\x)/, '').toLowerCase()
}

// ─── Stored Hash Decoding (ADR-032, 서버 stored-hash.ts와 같은 규칙) ──
export type StoredHashFormat = 'canonical' | 'legacy_text_hex' | 'invalid'

export interface StoredHash {
  /** 소문자 hex 64자 (32바이트). invalid면 null. */
  hex: string | null
  format: StoredHashFormat
}

/** ASCII hex 글자인 바이트인가: '0'-'9', 'a'-'f', 'A'-'F' */
function isHexAsciiByte(b: number): boolean {
  return (b >= 0x30 && b <= 0x39) || (b >= 0x61 && b <= 0x66) || (b >= 0x41 && b <= 0x46)
}

/** 저장된 bytea 값을 32바이트 해시(hex 64자)로 해석한다. 예외를 던지지 않는다. */
export function decodeStoredHash(value: unknown): StoredHash {
  try {
    if (typeof value !== 'string' || !value.startsWith('\\x')) return { hex: null, format: 'invalid' }
    const body = value.slice(2)
    if (body.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(body)) return { hex: null, format: 'invalid' }

    const byteLength = body.length / 2
    if (byteLength === 32) {
      return { hex: body.toLowerCase(), format: 'canonical' }
    }
    if (byteLength === 64) {
      let text = ''
      for (let i = 0; i < 64; i++) {
        const b = parseInt(body.substring(i * 2, i * 2 + 2), 16)
        if (!isHexAsciiByte(b)) return { hex: null, format: 'invalid' }
        text += String.fromCharCode(b)
      }
      return { hex: text.toLowerCase(), format: 'legacy_text_hex' }
    }
    return { hex: null, format: 'invalid' }
  } catch {
    return { hex: null, format: 'invalid' }
  }
}

function hexToBytes(hex: string): Uint8Array {
  const clean = normalizeHex(hex)
  const bytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substr(i, 2), 16)
  }
  return bytes
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

function isBase64(str: string): boolean {
  if (!str || str.length < 4) return false
  try { return /^[A-Za-z0-9+/]+=*$/.test(str) && btoa(atob(str)) === str }
  catch { return false }
}

// ─── SHA-256 (ADR-018 공식: SHA256(UTF8(hexString))) ────────
async function sha256Hex(hexString: string): Promise<string> {
  const bytes = new TextEncoder().encode(hexString)
  const hash = await crypto.subtle.digest('SHA-256', bytes.buffer as ArrayBuffer)
  return bytesToHex(new Uint8Array(hash))
}

// ─── V1: EC P-256 Signature Verification ────────────────────
function derToP1363(derSig: Uint8Array): Uint8Array | null {
  let offset = 0
  if (derSig[offset++] !== 0x30) return null
  const totalLen = derSig[offset++]
  if (totalLen & 0x80) offset += (totalLen & 0x7f)

  if (derSig[offset++] !== 0x02) return null
  const rLen = derSig[offset++]
  let r = derSig.slice(offset, offset + rLen)
  offset += rLen

  if (derSig[offset++] !== 0x02) return null
  const sLen = derSig[offset++]
  let s = derSig.slice(offset, offset + sLen)

  // Trim leading zeros, pad to 32 bytes
  while (r.length > 32 && r[0] === 0) r = r.slice(1)
  while (s.length > 32 && s[0] === 0) s = s.slice(1)
  const rPad = new Uint8Array(32); rPad.set(r, 32 - r.length)
  const sPad = new Uint8Array(32); sPad.set(s, 32 - s.length)

  const p1363 = new Uint8Array(64)
  p1363.set(rPad, 0)
  p1363.set(sPad, 32)
  return p1363
}

export async function verifySignatureV1(
  anchorRecordHex: string,
  signatureInput: string,
  publicKeyInput: string
): Promise<VerifyResult> {
  try {
    // Public key: detect BYTEA hex (\x...) vs base64
    let pubKeyBytes: Uint8Array
    const cleanPub = publicKeyInput.replace(/^\\\\x|^\\x/, '')
    if (/^[0-9a-fA-F]+$/.test(cleanPub) && cleanPub.length > 80) {
      // BYTEA hex format
      pubKeyBytes = hexToBytes(cleanPub)
    } else {
      // base64 DER SPKI format
      pubKeyBytes = base64ToBytes(publicKeyInput)
    }

    const key = await crypto.subtle.importKey(
      'spki', pubKeyBytes.buffer as ArrayBuffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false, ['verify']
    )

    // Signature: detect BYTEA hex (\x...) vs base64 vs plain hex
    let sigBytes: Uint8Array
    const cleanSig = signatureInput.replace(/^\\\\x|^\\x/, '')
    if (/^[0-9a-fA-F]+$/.test(cleanSig) && cleanSig.length >= 128) {
      sigBytes = hexToBytes(cleanSig)
    } else if (isBase64(signatureInput)) {
      sigBytes = base64ToBytes(signatureInput)
    } else {
      sigBytes = hexToBytes(signatureInput)
    }

    // Convert DER to P1363 if needed (Web Crypto requires P1363 = 64 bytes)
    if (sigBytes.length !== 64) {
      const converted = derToP1363(sigBytes)
      if (converted) sigBytes = converted
      else return { status: 'error', detail: '서명 형식 변환 실패 (DER→P1363)' }
    }

    // Sign target = UTF-8 encoded hex string of anchor_record
    const messageBytes = new TextEncoder().encode(anchorRecordHex)
    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key, sigBytes.buffer as ArrayBuffer, messageBytes.buffer as ArrayBuffer
    )

    return {
      status: valid ? 'pass' : 'fail',
      detail: valid ? 'EC P-256 서명 검증 통과' : '서명 불일치 — 변조 또는 다른 키로 서명됨',
    }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e)
    return { status: 'error', detail: `서명 검증 오류: ${msg}` }
  }
}

// ─── V2: Hash Chain Continuity Verification ─────────────────
export async function verifyChainV2(events: ChainEvent[]): Promise<V2Result> {
  if (!events || events.length === 0) {
    return { status: 'fail', detail: '체인 이벤트 없음' }
  }

  const sorted = [...events].sort((a, b) => a.seq - b.seq)

  // ADR-032: 루프 전에 모든 행의 저장 형식을 분류·해석한다 (서버 decodeStoredChainRows와 같음)
  let legacyTextHexRows = 0, invalidRows = 0
  const decoded = sorted.map(ev => {
    const payload = decodeStoredHash(ev.payload_hash)
    const prev = decodeStoredHash(ev.prev_hash)
    const chain = decodeStoredHash(ev.chain_hash)
    const hasContent = ev.content_hash !== null && ev.content_hash !== undefined
    const parts = [payload, prev, chain, ...(hasContent ? [decodeStoredHash(ev.content_hash)] : [])]
    if (parts.some(d => d.format === 'invalid')) invalidRows++
    else if (parts.some(d => d.format === 'legacy_text_hex')) legacyTextHexRows++
    return { payload: payload.hex ?? '', prev: prev.hex ?? '', chain: chain.hex ?? '' }
  })

  if (invalidRows > 0) {
    return {
      status: 'fail',
      detail: `저장 형식을 해석할 수 없는 행 ${invalidRows}개`,
      legacyTextHexRows,
      invalidRows,
    }
  }

  let gaps = 0, captures = 0, continuityCount = 0, blanks = 0
  let firstTs: string | null = null
  let lastTs: string | null = null

  for (let i = 0; i < sorted.length; i++) {
    const ev = sorted[i]
    const evType = ev.event_type

    if (evType === 'capture') captures++
    else if (evType === 'continuity') continuityCount++
    else if (evType === 'blank') blanks++
    else if (evType === 'gap') gaps++

    const ts = ev.ts_utc_raw || ev.ts_utc
    if (i === 0) firstTs = ts
    lastTs = ts

    // Genesis: prev_hash must be all zeros
    if (i === 0 && evType === 'genesis') {
      const prevHash = decoded[i].prev
      if (prevHash !== '0'.repeat(64)) {
        return { status: 'fail', detail: `genesis prev_hash가 영이 아님 (seq=${ev.seq})`, legacyTextHexRows, invalidRows }
      }
    }

    // Chain link: prev_hash must equal previous event's chain_hash
    if (i > 0) {
      const expectedPrev = decoded[i - 1].chain
      const actualPrev = decoded[i].prev
      if (expectedPrev !== actualPrev) {
        return { status: 'fail', detail: `해시체인 끊김 — seq=${ev.seq}의 prev_hash 불일치`, legacyTextHexRows, invalidRows }
      }
    }

    // chain_hash = SHA256(UTF8(hex(prev_bytes || payload_bytes || uint32BE(seq) || utf8(ts))))
    // 서버 _shared/verify-chain.ts 와 동일 (DataSchema v1.3 §3.3)
    const prevBytes = hexToBytes(decoded[i].prev)
    const payloadBytes = hexToBytes(decoded[i].payload)
    const seqBytes = uint32BE(ev.seq)
    const tsForHash = ev.ts_utc_raw || ev.ts_utc
    const tsBytes = new TextEncoder().encode(tsForHash)
    const combined = concatBytes(prevBytes, payloadBytes, seqBytes, tsBytes)
    const expectedChainHash = await sha256Hex(bytesToHex(combined))
    const actualChainHash = decoded[i].chain

    if (expectedChainHash !== actualChainHash) {
      return { status: 'fail', detail: `chain_hash 불일치 — seq=${ev.seq} (${evType})`, legacyTextHexRows, invalidRows }
    }
  }

  return {
    status: 'pass',
    detail: `${sorted.length}개 이벤트, ${gaps}개 갭, 체인 무결성 통과`,
    legacyTextHexRows,
    invalidRows,
    summary: {
      total_events: sorted.length,
      captures,
      continuity_records: continuityCount,
      gaps,
      blanks,
      started_at: firstTs,
      ended_at: lastTs,
    },
  }
}

// ─── V3: Retry helper for transient network errors ──────────
async function fetchWithRetry(
  fetchFn: () => Promise<any>,
  retries = 3,
  delayMs = 1000
): Promise<any> {
  for (let i = 0; i < retries; i++) {
    try {
      return await fetchFn()
    } catch (err) {
      if (i < retries - 1) {
        await new Promise((r) => setTimeout(r, delayMs))
      } else {
        throw err
      }
    }
  }
}

// ─── V3: getAttestation 응답 해석 (C1) ──────────────────────
// eth_call 결과는 동적 구조체 하나: 0번 단어 = 오프셋 0x20, 그 뒤 구조체 (1번 단어부터).
//   1 uid · 2 schema · 3 time · … · 8 attester · 9 revocable · 10 data 오프셋(구조체 시작 기준)
//   data 길이 단어 = 1 + 오프셋/32, 그다음 단어가 data 첫 칸 (= anchor_record)
// 없는 UID도 빈 구조체가 돌아온다 (0번 0x20, 10번 0x140, 나머지 0) → uid 대조로 미존재를 가린다.
export interface AttestationHead {
  uid: string
  time: number
  dataFirstWord: string | null
}

const TWO_POW_53 = BigInt(2) ** BigInt(53)

/** getAttestation 응답의 앞부분을 읽는다. 해석할 수 없으면 null. 예외를 던지지 않는다. */
export function decodeAttestationHead(resultHex: unknown): AttestationHead | null {
  try {
    if (typeof resultHex !== 'string' || !/^0x[0-9a-fA-F]*$/.test(resultHex)) return null
    const body = resultHex.slice(2).toLowerCase()
    if (body.length % 64 !== 0) return null
    const count = body.length / 64
    if (count < 11) return null
    const word = (i: number) => body.slice(i * 64, (i + 1) * 64)

    if (BigInt('0x' + word(0)) !== BigInt(32)) return null

    const timeBig = BigInt('0x' + word(3))
    if (timeBig >= TWO_POW_53) return null

    let dataFirstWord: string | null = null
    const offset = BigInt('0x' + word(10))
    if (offset % BigInt(32) === BigInt(0) && offset < BigInt(count * 32)) {
      const lenIdx = 1 + Number(offset / BigInt(32))
      if (lenIdx + 1 < count && BigInt('0x' + word(lenIdx)) >= BigInt(32)) {
        dataFirstWord = word(lenIdx + 1)
      }
    }

    return { uid: word(1), time: Number(timeBig), dataFirstWord }
  } catch {
    return null
  }
}

function cleanHex(v: unknown): string {
  return typeof v === 'string' ? v.replace(/^0x/i, '').toLowerCase() : ''
}

/** 응답을 요청 UID·이 증명의 anchor_record와 대조해 클라이언트 V3 판정을 낸다 (C1 D4). 예외를 던지지 않는다. */
export function evaluateAttestation(
  resultHex: unknown,
  requestedUid: string,
  anchorRecordHex: string | null | undefined,
  chainName: string
): { status: 'pass' | 'fail' | 'error'; detail: string; attestationTime?: string } {
  const head = decodeAttestationHead(resultHex)
  if (!head) return { status: 'error', detail: '온체인 응답 해석 불가' }

  const requested = cleanHex(requestedUid).padStart(64, '0')
  if (/^0+$/.test(head.uid) || head.uid !== requested) {
    return { status: 'fail', detail: '온체인 어테스테이션 미존재' }
  }

  const ar = cleanHex(anchorRecordHex)
  if (!/^[0-9a-f]{64}$/.test(ar)) {
    return { status: 'pass', detail: '온체인 기록 존재 · 대조 안 함' }
  }

  if (head.dataFirstWord === null || head.dataFirstWord !== ar) {
    return { status: 'fail', detail: '온체인 기록 불일치 (anchor_record)' }
  }

  return {
    status: 'pass',
    detail: `온체인 기록 일치 (${chainName})`,
    ...(head.time > 0 ? { attestationTime: new Date(head.time * 1000).toISOString() } : {}),
  }
}

// ─── V3: EAS On-Chain Verification (ethers.js 없이 JSON-RPC 직접 호출) ──
// Sprint 9-2: chain_id 기반 RPC/EAS 동적 선택
export async function verifyOnChainV3(
  easUid: string,
  chainId: number | null | undefined,
  anchorRecordHex?: string
): Promise<V3Result> {
  if (!easUid) return { status: 'pending', detail: '온체인 기록 없음 (eas_uid 없음)' }

  const cfg = getChainConfig(chainId)
  if (!cfg) {
    return { status: 'error', detail: `Unsupported chain_id: ${chainId}` }
  }

  try {
    // getAttestation(bytes32) selector = 0xa3112a64
    const uidClean = easUid.startsWith('0x') ? easUid.slice(2) : easUid
    const calldata = '0xa3112a64' + uidClean.padStart(64, '0')

    const result = await fetchWithRetry(() =>
      fetch(cfg.rpc, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0', id: 1, method: 'eth_call',
          params: [{ to: cfg.eas, data: calldata }, 'latest'],
        }),
      }).then(r => r.json())
    )
    if (result.error) {
      return { status: 'error', detail: `RPC 오류: ${result.error.message}` }
    }

    const data = result.result
    if (!data || data === '0x' || /^0x0+$/.test(data)) {
      return { status: 'fail', detail: '온체인 어테스테이션 미존재' }
    }

    const evaluated = evaluateAttestation(data, easUid, anchorRecordHex, cfg.name)
    if (evaluated.status !== 'pass') return evaluated

    return {
      ...evaluated,
      easscan_url: `${cfg.easscanBase}/${easUid}`,
    }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e)
    return { status: 'error', detail: `온체인 조회 실패: ${msg}` }
  }
}

// ─── OT: Origin Tag + Anchor Record Recalculation ───────────
function tlvEncode(tag: number, value: Uint8Array): Uint8Array {
  const result = new Uint8Array(3 + value.length)
  result[0] = tag
  result[1] = (value.length >> 8) & 0xff
  result[2] = value.length & 0xff
  result.set(value, 3)
  return result
}

function uint64Bytes(val: number | bigint): Uint8Array {
  const buf = new Uint8Array(8)
  let n = BigInt(val)
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(n & 0xffn)
    n >>= 8n
  }
  return buf
}

function uint32BE(val: number): Uint8Array {
  const buf = new Uint8Array(4)
  buf[0] = (val >>> 24) & 0xff
  buf[1] = (val >>> 16) & 0xff
  buf[2] = (val >>> 8) & 0xff
  buf[3] = val & 0xff
  return buf
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) { out.set(p, off); off += p.length }
  return out
}

export interface OTPreimage {
  eh: string
  f: string
  sh: string
  fpid: string
  pv: string
  ts: number
  ctr: number
  lh_prev: string
  sid: string
}

export async function verifyOT(
  originTag: string,
  anchorRecord: string,
  chainContinuityHash: string,
  preimage: OTPreimage
): Promise<VerifyResult> {
  try {
    const eh = hexToBytes(normalizeHex(preimage.eh))

    // F field: 64-char hex takes precedence over base64 (hex chars are valid base64)
    let fBytes: Uint8Array
    const fStr = preimage.f || ''
    if (/^[0-9a-fA-F]{64}$/.test(fStr)) {
      fBytes = hexToBytes(fStr)
    } else if (fStr && isBase64(fStr)) {
      const decoded = base64ToBytes(fStr)
      if (decoded.length === 32) {
        fBytes = decoded
      } else if (decoded.length === 64) {
        const asHex = new TextDecoder().decode(decoded)
        fBytes = /^[0-9a-fA-F]{64}$/.test(asHex) ? hexToBytes(asHex) : decoded
      } else {
        fBytes = decoded
      }
    } else {
      fBytes = new Uint8Array(32)
    }

    const sh = hexToBytes(normalizeHex(preimage.sh))
    // UUID may contain hyphens — strip before hex parse
    const fpid = hexToBytes(normalizeHex(preimage.fpid).replace(/-/g, ''))
    // PV padded to 4 bytes
    const pvRaw = new TextEncoder().encode(preimage.pv || 'v1.0')
    const pv = new Uint8Array(4); pv.set(pvRaw.slice(0, 4))
    const ts = uint64Bytes(preimage.ts)
    const ctr = uint64Bytes(preimage.ctr)
    const lh = hexToBytes(normalizeHex(preimage.lh_prev))
    const sid = hexToBytes(normalizeHex(preimage.sid).replace(/-/g, ''))

    const tlvParts = [
      tlvEncode(0x01, eh), tlvEncode(0x02, fBytes), tlvEncode(0x03, sh),
      tlvEncode(0x04, fpid), tlvEncode(0x05, pv), tlvEncode(0x06, ts),
      tlvEncode(0x07, ctr), tlvEncode(0x08, lh), tlvEncode(0x09, sid),
    ]

    const totalLen = tlvParts.reduce((sum, p) => sum + p.length, 0)
    const tlvBytes = new Uint8Array(totalLen)
    let offset = 0
    for (const part of tlvParts) { tlvBytes.set(part, offset); offset += part.length }

    // OT = SHA256(hex(tlvBytes)) — ADR-018 공식
    const otRecalc = await sha256Hex(bytesToHex(tlvBytes))
    const storedOT = normalizeHex(originTag)

    if (otRecalc !== storedOT) {
      return { status: 'fail', detail: 'Origin Tag 불일치 — 데이터 변조 의심' }
    }

    // anchor_record = SHA256(hex('OS_V1') || OT || CCH)
    const prefix = bytesToHex(new TextEncoder().encode('OS_V1'))
    const arPreimage = prefix + storedOT + normalizeHex(chainContinuityHash)
    const arRecalc = await sha256Hex(arPreimage)
    const storedAR = normalizeHex(anchorRecord)

    if (arRecalc !== storedAR) {
      return { status: 'fail', detail: 'Anchor Record 불일치 — 앵커 변조 의심' }
    }

    return { status: 'pass', detail: 'Origin Tag + Anchor Record 재계산 일치' }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e)
    return { status: 'error', detail: `OT 검증 오류: ${msg}` }
  }
}
