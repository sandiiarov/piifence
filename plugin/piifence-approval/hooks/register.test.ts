import { expect, test } from 'claude-code/testing'

const KEY = 'if-ajsdlk231lj12kl12j1'
const PROMPT = `use this API key ${KEY} please`

// Stands for the gateway and the engine: /scan finds the key, env.set and
// toast succeed, and every AskUserQuestion dialog is counted.
function engine(on) {
  const seen = { asks: 0, env: [], raw: 0 }
  on('http.fetch', (_, e) => {
    if (e.url.endsWith('/control/allow-prompt-once')) {
      seen.raw += 1
      return { value: { status: 200, ok: true, headers: {}, text: '{}' } }
    }
    const start = PROMPT.indexOf(KEY)
    const findings = [
      { label: 'secret', start, end: start + KEY.length, preview: 'if-a…12j1' },
    ]
    return { value: { status: 200, ok: true, headers: {}, text: JSON.stringify({ findings }) } }
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
  expect(result.text).toBe('use this API key $PIIF_SECRET_1 please')
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
