// src/lib/display.test.mjs
// C1 — 앵커링 상태·간격·등급 근거 문구 (ADR-028)
// 실행: node --test src/lib/display.test.mjs   (Node ≥ 22.18, 의존성 없음)
// 시각·체인 이름은 고정 문자열로 넣는다 (서식은 ProofCard가 한다)

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  LATE_ANCHOR_MS, formatInterval, computeInterval, describeInterval,
  pickRecordTime, shouldShowServerTime, pendingAnchorText, recordStateLabel,
  verifiedTail, gradeBasisLine, gradeRuleLine,
} from './display.ts'

const SEC = 1000, MIN = 60 * SEC, HOUR = 60 * MIN, DAY = 24 * HOUR

test('#1 formatInterval: 경계값', () => {
  const cases = [
    [6500, '6초'], [59999, '59초'], [60000, '1분 0초'], [3599000, '59분 59초'],
    [3600000, '1시간 0분'], [172799000, '47시간 59분'], [172800000, '2일'], [190 * DAY, '190일'],
  ]
  for (const [ms, want] of cases) assert.equal(formatInterval(ms), want, String(ms))
  assert.equal(LATE_ANCHOR_MS, 10 * MIN)
})

test('#2 간격 계산: 음수, 촬영 시각 없음, 해석 안 되는 문자열 → 예외 없음', () => {
  const rec = '2026-11-13T14:13:18Z'
  const neg = computeInterval('2026-11-13T14:13:19Z', rec)
  assert.deepEqual(neg, { kind: 'negative' })
  assert.equal(describeInterval(neg), '촬영 시각이 기록 시각보다 늦습니다 (기기 시계 확인 필요)')
  for (const [c, r] of [[undefined, rec], [null, rec], ['', rec], ['not-a-date', rec], ['2026-11-13T14:12:48Z', 'garbage']]) {
    const it = computeInterval(c, r)
    assert.deepEqual(it, { kind: 'unknown' })
    assert.equal(describeInterval(it), '간격 계산 불가')
  }
  const ok = computeInterval('2026-11-13T14:12:48Z', rec)
  assert.deepEqual(ok, { kind: 'ok', ms: 30 * SEC })
  assert.equal(describeInterval(ok), '30초')
})

test('#3 기록 시각 출처: 온체인만 / 서버만 / 둘 다 / 둘 다 없음', () => {
  const on = '2026-11-13T14:13:18.000Z', sv = '2026-11-13T14:13:20.000Z'
  assert.deepEqual(pickRecordTime(on, null), { time: on, source: '온체인' })
  assert.deepEqual(pickRecordTime(undefined, sv), { time: sv, source: '서버 기록' })
  assert.deepEqual(pickRecordTime(on, sv), { time: on, source: '온체인' })
  assert.deepEqual(pickRecordTime(undefined, null), { time: null, source: null })
})

test('#4 서버 기록 시각 줄: 차이 0.5초 숨김 / 1.5초 표시', () => {
  const on = '2026-11-13T14:13:18.000Z'
  assert.equal(shouldShowServerTime(on, '2026-11-13T14:13:18.500Z'), false)
  assert.equal(shouldShowServerTime(on, '2026-11-13T14:13:19.500Z'), true)
  assert.equal(shouldShowServerTime(on, on), false)
  assert.equal(shouldShowServerTime(undefined, '2026-11-13T14:13:19.500Z'), false)
  assert.equal(shouldShowServerTime(on, null), false)
})

test('#5 상태 문구: state 6종 + undefined + 모르는 문자열 (PENDING_ANCHOR)', () => {
  const NEXT = '2026. 11. 14. 오후 03:00:00 KST'
  const want = {
    pending: ['블록체인 기록 대기 중', '◎ 이 사진은 아직 블록체인에 기록되지 않았습니다. 기록 대기 중입니다.'],
    processing: ['블록체인 기록 처리 중', '◎ 이 사진의 블록체인 기록을 처리하고 있습니다. 잠시 후 다시 확인해 주세요.'],
    retry_scheduled: ['블록체인 기록 재시도 예정', `◎ 이 사진은 아직 블록체인에 기록되지 않았습니다. 기록 시도가 실패했고, 다음 시도가 ${NEXT}에 예정되어 있습니다.`],
    on_hold: ['블록체인 미기록 (보류)', '◎ 이 사진은 블록체인에 기록되지 않았습니다. 기록이 보류되어 있습니다.'],
    failed_final: ['블록체인 기록 실패', '◎ 이 사진은 블록체인에 기록되지 않았습니다. 기록 시도가 실패로 끝났으며 자동으로 다시 시도하지 않습니다.'],
  }
  for (const [state, [title, summary]] of Object.entries(want)) {
    assert.deepEqual(pendingAnchorText(state, NEXT), { title, summary }, state)
  }
  const unknown = { title: '앵커링 상태 확인 불가', summary: '◎ 이 사진의 블록체인 기록 상태를 확인할 수 없습니다.' }
  // completed는 PENDING_ANCHOR 표에 없으므로 "그 밖"
  for (const state of ['completed', undefined, null, 'weird_state', 42, 'toString', '__proto__']) {
    assert.deepEqual(pendingAnchorText(state, NEXT), unknown, String(state))
  }
})

test('#6 상태 문구: retry_scheduled + next_attempt_at 없음 → "기록 시도가 실패했습니다."로 끝남', () => {
  for (const next of [null, undefined, '']) {
    const { summary } = pendingAnchorText('retry_scheduled', next)
    assert.ok(summary.endsWith('기록 시도가 실패했습니다.'), summary)
    assert.ok(!summary.includes('다음 시도'))
  }
})

test('#6b 기록 칸 상태 줄', () => {
  assert.equal(recordStateLabel('completed'), '기록 완료')
  assert.equal(recordStateLabel('on_hold'), '블록체인 미기록 (보류)')
  assert.equal(recordStateLabel('processing'), '블록체인 기록 처리 중')
  assert.equal(recordStateLabel(undefined), '앵커링 상태 확인 불가')
  assert.equal(recordStateLabel('weird'), '앵커링 상태 확인 불가')
})

test('#7 VERIFIED 뒷부분', () => {
  const T = '2026. 07. 21. 오후 09:45:33 KST'
  const row1 = '블록체인 기록은 테스트 체인(Ethereum Sepolia)에 있으며 운영 체인 기록이 아닙니다.'
  const row2 = '블록체인에 기록되어 있습니다. 촬영과 기록 사이의 간격은 확인할 수 없습니다.'
  const row3 = d => `블록체인 기록은 촬영 ${d} 뒤(${T})에 이루어졌습니다. 이 기록은 그 시각 이후로 내용이 바뀌지 않았음을 뜻합니다.`
  const row4 = '촬영 이후 변조된 흔적이 없으며, 블록체인에 기록되어 있습니다.'
  const v = (gradeBasis, interval, chainName = 'Polygon PoS') => verifiedTail({ gradeBasis, interval, recordTimeText: T, chainName })

  assert.equal(v('non_mainnet_anchor', { kind: 'ok', ms: 5 * SEC }, 'Ethereum Sepolia'), row1)
  assert.equal(v('mainnet_anchor', { kind: 'ok', ms: 9 * MIN + 59 * SEC }), row4)
  assert.equal(v('mainnet_anchor', { kind: 'ok', ms: 10 * MIN }), row3('10분 0초'))
  assert.equal(v('mainnet_anchor', { kind: 'ok', ms: 190 * DAY }), row3('190일'))
  assert.equal(v('mainnet_anchor', { kind: 'negative' }), row2)
  assert.equal(v('mainnet_anchor', { kind: 'unknown' }), row2)
  // non_mainnet이 간격보다 먼저
  assert.equal(v('non_mainnet_anchor', { kind: 'ok', ms: 190 * DAY }, 'Ethereum Sepolia'), row1)
})

test('#8 등급 근거 첫 줄: 등급 글자는 입력값을 따른다', () => {
  const basis = {
    mainnet_anchor: '운영 체인(Polygon)에 기록됨',
    non_mainnet_anchor: '기록은 있으나 운영 체인이 아님 (테스트 체인)',
    unverifiable_uid: '기록 식별자를 확인할 수 없음',
    no_anchor: '블록체인 기록 없음',
  }
  for (const [b, text] of Object.entries(basis)) {
    assert.equal(gradeBasisLine(b, 'A'), `블록체인 A — ${text}`)
    assert.equal(gradeBasisLine(b, 'D'), `블록체인 D — ${text}`)
    assert.equal(gradeBasisLine(b, undefined), `블록체인 — — ${text}`)
  }
  assert.equal(gradeBasisLine(null, 'A'), '블록체인 등급 근거 정보 없음')
  assert.equal(gradeBasisLine(undefined, 'D'), '블록체인 등급 근거 정보 없음')
  assert.equal(gradeBasisLine('future_basis', 'A'), '블록체인 등급 근거: future_basis')
})

test('#9 등급 둘째 줄', () => {
  const T = '2026. 11. 13. 오후 11:13:30 KST'
  assert.equal(gradeRuleLine(2, T), `등급 규칙 v2 · ${T} 기록`)
  assert.equal(gradeRuleLine(2, null), '등급 규칙 v2')
  assert.equal(gradeRuleLine(null, T), `${T} 기록`)
  assert.equal(gradeRuleLine(undefined, undefined), null)
  assert.equal(gradeRuleLine(null, ''), null)
})
