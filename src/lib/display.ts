// ─── OriginSeal Verifier 화면 문구 (C1, ADR-028) ─────────────
// 화면의 모든 단언은 그 순간 조회한 데이터로 소급할 수 있어야 한다.
// 조회하지 않은 것은 단언하지 않고, 모르는 상태는 숨기지 않고 "확인 불가"로 쓴다.
//
// 규칙:
//   - import 없음, 예외를 던지지 않음, JSX를 반환하지 않음 (display.test.mjs가 Node로 직접 불러온다)
//   - 시각 서식은 하지 않는다. 기록 시각·다음 시도 시각·등급 기록 시각·체인 이름은
//     호출하는 쪽(ProofCard)이 서식한 문자열로 받는다
//   - 이 파일 안의 시간 계산은 간격(formatInterval, computeInterval)뿐이다
//   - 앵커링 상태는 서버가 준 anchoring.state만 쓴다. proofs 행에서 다시 계산하지 않는다 (D5)

/** 이 간격 이상이면 VERIFIED 요약 문장에 간격을 적는다 (D2). 정상 경로는 6~60초 */
export const LATE_ANCHOR_MS = 10 * 60 * 1000

// ─── 간격 ────────────────────────────────────────────────────
/** 60초 미만 N초, 60분 미만 N분 M초, 48시간 미만 N시간 M분, 그 이상 N일 (모두 버림) */
export function formatInterval(ms: number): string {
  const totalSec = Math.floor(Math.max(0, ms) / 1000)
  if (totalSec < 60) return `${totalSec}초`
  const totalMin = Math.floor(totalSec / 60)
  if (totalMin < 60) return `${totalMin}분 ${totalSec % 60}초`
  const totalHour = Math.floor(totalMin / 60)
  if (totalHour < 48) return `${totalHour}시간 ${totalMin % 60}분`
  return `${Math.floor(totalHour / 24)}일`
}

export type IntervalResult =
  | { kind: 'ok'; ms: number }
  | { kind: 'negative' }
  | { kind: 'unknown' }

export const INTERVAL_NEGATIVE_TEXT = '촬영 시각이 기록 시각보다 늦습니다 (기기 시계 확인 필요)'
export const INTERVAL_UNKNOWN_TEXT = '간격 계산 불가'

function parseTime(v: unknown): number | null {
  if (typeof v !== 'string' || v === '') return null
  const t = Date.parse(v)
  return Number.isFinite(t) ? t : null
}

/** 간격 = 기록 시각 − 촬영 시각. 둘 중 하나가 없거나 해석되지 않으면 unknown */
export function computeInterval(capturedAt: unknown, recordedAt: unknown): IntervalResult {
  const c = parseTime(capturedAt)
  const r = parseTime(recordedAt)
  if (c === null || r === null) return { kind: 'unknown' }
  const ms = r - c
  if (ms < 0) return { kind: 'negative' }
  return { kind: 'ok', ms }
}

export function describeInterval(interval: IntervalResult): string {
  if (interval.kind === 'ok') return formatInterval(interval.ms)
  if (interval.kind === 'negative') return INTERVAL_NEGATIVE_TEXT
  return INTERVAL_UNKNOWN_TEXT
}

// ─── 기록 시각 출처 (D1) ─────────────────────────────────────
export interface RecordTime {
  time: string | null
  /** 화면에 붙이는 출처 */
  source: '온체인' | '서버 기록' | null
}

/** 온체인 값(클라이언트 V3가 anchor_record까지 대조한 뒤 준 값)이 있으면 그것, 없으면 서버 anchored_at */
export function pickRecordTime(onchain: unknown, server: unknown): RecordTime {
  if (typeof onchain === 'string' && onchain !== '') return { time: onchain, source: '온체인' }
  if (typeof server === 'string' && server !== '') return { time: server, source: '서버 기록' }
  return { time: null, source: null }
}

/** 온체인 값과 서버 값이 둘 다 있고 1초 넘게 다를 때만 서버 기록 시각 줄을 보인다. 판정하지 않는다 */
export function shouldShowServerTime(onchain: unknown, server: unknown): boolean {
  const o = parseTime(onchain)
  const s = parseTime(server)
  if (o === null || s === null) return false
  return Math.abs(o - s) > 1000
}

// ─── 앵커링 상태 (§1-2) ─────────────────────────────────────
const UNKNOWN_TITLE = '앵커링 상태 확인 불가'

const STATE_TITLE: Record<string, string> = {
  pending: '블록체인 기록 대기 중',
  processing: '블록체인 기록 처리 중',
  retry_scheduled: '블록체인 기록 재시도 예정',
  on_hold: '블록체인 미기록 (보류)',
  failed_final: '블록체인 기록 실패',
}

function stateKey(state: unknown): string | null {
  return typeof state === 'string' && Object.prototype.hasOwnProperty.call(STATE_TITLE, state) ? state : null
}

/**
 * overall_result가 PENDING_ANCHOR일 때의 제목과 요약 문장.
 * nextAttemptText는 호출하는 쪽이 서식한 next_attempt_at (없으면 null)
 */
export function pendingAnchorText(state: unknown, nextAttemptText: string | null | undefined): { title: string; summary: string } {
  const key = stateKey(state)
  switch (key) {
    case 'pending':
      return { title: STATE_TITLE.pending, summary: '◎ 이 사진은 아직 블록체인에 기록되지 않았습니다. 기록 대기 중입니다.' }
    case 'processing':
      return { title: STATE_TITLE.processing, summary: '◎ 이 사진의 블록체인 기록을 처리하고 있습니다. 잠시 후 다시 확인해 주세요.' }
    case 'retry_scheduled':
      return {
        title: STATE_TITLE.retry_scheduled,
        summary: nextAttemptText
          ? `◎ 이 사진은 아직 블록체인에 기록되지 않았습니다. 기록 시도가 실패했고, 다음 시도가 ${nextAttemptText}에 예정되어 있습니다.`
          : '◎ 이 사진은 아직 블록체인에 기록되지 않았습니다. 기록 시도가 실패했습니다.',
      }
    case 'on_hold':
      return { title: STATE_TITLE.on_hold, summary: '◎ 이 사진은 블록체인에 기록되지 않았습니다. 기록이 보류되어 있습니다.' }
    case 'failed_final':
      return {
        title: STATE_TITLE.failed_final,
        summary: '◎ 이 사진은 블록체인에 기록되지 않았습니다. 기록 시도가 실패로 끝났으며 자동으로 다시 시도하지 않습니다.',
      }
    default:
      return { title: UNKNOWN_TITLE, summary: '◎ 이 사진의 블록체인 기록 상태를 확인할 수 없습니다.' }
  }
}

/** "블록체인 기록" 칸의 상태 줄. completed이면 "기록 완료", 그 밖은 §1-2의 제목 */
export function recordStateLabel(state: unknown): string {
  if (state === 'completed') return '기록 완료'
  const key = stateKey(state)
  return key ? STATE_TITLE[key] : UNKNOWN_TITLE
}

// ─── VERIFIED 요약 문장 뒷부분 (§1-3) ───────────────────────
export const VERIFIED_TAIL_DEFAULT = '촬영 이후 변조된 흔적이 없으며, 블록체인에 기록되어 있습니다.'

/**
 * 위에서부터 처음 맞는 줄.
 * recordTimeText: 서식한 기록 시각 (KST). chainName: 서식한 체인 이름
 */
export function verifiedTail(args: {
  gradeBasis: unknown
  interval: IntervalResult
  recordTimeText: string
  chainName: string
}): string {
  const { gradeBasis, interval, recordTimeText, chainName } = args
  if (gradeBasis === 'non_mainnet_anchor') {
    return `블록체인 기록은 테스트 체인(${chainName})에 있으며 운영 체인 기록이 아닙니다.`
  }
  if (interval.kind !== 'ok') {
    return '블록체인에 기록되어 있습니다. 촬영과 기록 사이의 간격은 확인할 수 없습니다.'
  }
  if (interval.ms >= LATE_ANCHOR_MS) {
    return `블록체인 기록은 촬영 ${formatInterval(interval.ms)} 뒤(${recordTimeText})에 이루어졌습니다. 이 기록은 그 시각 이후로 내용이 바뀌지 않았음을 뜻합니다.`
  }
  return VERIFIED_TAIL_DEFAULT
}

// ─── 등급 근거 (§1-5) ───────────────────────────────────────
/** 첫 줄. 등급 글자는 grade_subscores.blockchain_anchoring 값을 그대로 넣는다 */
export function gradeBasisLine(gradeBasis: unknown, blockchainGrade: unknown): string {
  const g = typeof blockchainGrade === 'string' && blockchainGrade !== '' ? blockchainGrade : '—'
  if (gradeBasis === null || gradeBasis === undefined || gradeBasis === '') return '블록체인 등급 근거 정보 없음'
  switch (gradeBasis) {
    case 'mainnet_anchor': return `블록체인 ${g} — 운영 체인(Polygon)에 기록됨`
    case 'non_mainnet_anchor': return `블록체인 ${g} — 기록은 있으나 운영 체인이 아님 (테스트 체인)`
    case 'unverifiable_uid': return `블록체인 ${g} — 기록 식별자를 확인할 수 없음`
    case 'no_anchor': return `블록체인 ${g} — 블록체인 기록 없음`
    default: return `블록체인 등급 근거: ${String(gradeBasis)}`
  }
}

/** 둘째 줄. computedAtText는 서식한 grade_computed_at. 둘 다 없으면 null (줄을 그리지 않음) */
export function gradeRuleLine(ruleVersion: unknown, computedAtText: string | null | undefined): string | null {
  const hasVersion = (typeof ruleVersion === 'number' && Number.isFinite(ruleVersion))
    || (typeof ruleVersion === 'string' && ruleVersion !== '')
  const parts: string[] = []
  if (hasVersion) parts.push(`등급 규칙 v${ruleVersion}`)
  if (computedAtText) parts.push(`${computedAtText} 기록`)
  return parts.length > 0 ? parts.join(' · ') : null
}
