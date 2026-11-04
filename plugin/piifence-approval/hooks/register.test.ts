import { expect, test } from 'claude-code/testing'

const KEY = 'if-ajsdlk231lj12kl12j1'
const PROMPT = `use this API key ${KEY} please`

// Stands for the gateway and the engine: /scan finds the key, env.set and
// toast succeed, and every AskUserQuestion dialog is counted. `autoApprove`
// is what config.toml's `auto_approve` makes /scan return. Values sent to /control/env-values are recorded; `envValuesOk: false` makes that call fail.
function engine(on, autoApprove = null, { envValuesOk = true } = {}) {
  const seen = { asks: 0, env: [], raw: 0, envValues: [] }
  on('http.fetch', (_, e) => {
    if (e.url.endsWith('/control/env-values')) {
      seen.envValues.push(...JSON.parse(e.init.body).values)
      const status = envValuesOk ? 200 : 500
      return { value: { status, ok: envValuesOk, headers: {}, text: '{}' } }
    }
    if (e.url.endsWith('/control/allow-prompt-once')) {
      seen.raw += 1
      return { value: { status: 200, ok: true, headers: {}, text: '{}' } }
    }
    const start = PROMPT.indexOf(KEY)
    const findings = [
      { label: 'secret', start, end: start + KEY.length, preview: 'if-a…12j1' },
    ]
    return { value: { status: 200, ok: true, headers: {}, text: JSON.stringify({ findings, auto_approve: autoApprove }) } }
  })
  on('env.get', () => ({ value: undefined }))
  on('env.set', (_, e) => {
    seen.env.push(e.name)
    return { value: undefined }
  })
  on('ui.toast', () => ({ value: undefined }))
  on('tool.call', { tool: 'AskUserQuestion' }, () => {
    seen.asks += 1
    return { result: {} }
  })
  on('prompt.submit', (_, e) => e)
  return seen
}

test('without the setting the dialog is shown', async ($, on) => {
  const seen = engine(on)
  await $.prompt.submit({ text: PROMPT })
  expect(seen.asks).toBe(1)
})

test('replace swaps the value for an env var without asking', { options: { autoApprovePiiFence: 'replace' } }, async ($, on) => {
  const seen = engine(on)
  const result = await $.prompt.submit({ text: PROMPT })
  expect(seen.asks).toBe(0)
  expect(seen.env).toEqual(['PIIF_SECRET_1'])
  expect(seen.envValues).toEqual([{ name: 'PIIF_SECRET_1', value: KEY, label: 'secret' }])
  expect(result.text).toBe('use this API key $PIIF_SECRET_1 please')
})

test('replace blocks the prompt when the gateway cannot take the values', { options: { autoApprovePiiFence: 'replace' } }, async ($, on) => {
  const seen = engine(on, null, { envValuesOk: false })
  const result = await $.prompt.submit({ text: PROMPT })
  expect(seen.env).toEqual([])
  expect('drop' in result).toBe(true)
})

test('redact passes the prompt on unchanged without asking', { options: { autoApprovePiiFence: 'redact' } }, async ($, on) => {
  const seen = engine(on)
  const result = await $.prompt.submit({ text: PROMPT })
  expect(seen.asks).toBe(0)
  expect(seen.env).toEqual([])
  expect(result.text).toBe(PROMPT)
})

test('send-raw authorizes the prompt once without asking', { options: { autoApprovePiiFence: 'send-raw' } }, async ($, on) => {
  const seen = engine(on)
  const result = await $.prompt.submit({ text: PROMPT })
  expect(seen.asks).toBe(0)
  expect(seen.raw).toBe(1)
  expect(result.text).toBe(PROMPT)
})

test('block drops the prompt without asking', { options: { autoApprovePiiFence: 'block' } }, async ($, on) => {
  const seen = engine(on)
  const result = await $.prompt.submit({ text: PROMPT })
  expect(seen.asks).toBe(0)
  expect('drop' in result).toBe(true)
})

test('config.toml auto_approve applies without the setting', async ($, on) => {
  const seen = engine(on, 'block')
  const result = await $.prompt.submit({ text: PROMPT })
  expect(seen.asks).toBe(0)
  expect('drop' in result).toBe(true)
})

test('the Claude Code setting wins over config.toml', { options: { autoApprovePiiFence: 'redact' } }, async ($, on) => {
  const seen = engine(on, 'block')
  const result = await $.prompt.submit({ text: PROMPT })
  expect(seen.asks).toBe(0)
  expect(result.text).toBe(PROMPT)
})
