import { expect, test } from 'claude-code/testing'

const KEY = 'if-ajsdlk231lj12kl12j1'
const PROMPT = `use this API key ${KEY} please`

const SESSION = '0123456789abcdef0123456789abcdef'

// Stands for the gateway and the engine: /scan finds the key and names it $PIIF_SECRET_1, env.set and toast succeed, and every AskUserQuestion dialog is counted. `autoApprove` is what config.toml's `auto_approve` makes /scan return. Values sent to /control/env-values are recorded; `envValuesOk: false` makes that call fail. /control/env-lookup answers from `lookup`. Every gateway call is recorded with its body and session header.
function engine(on, autoApprove = null, { envValuesOk = true, lookup = {} } = {}) {
  const seen = { asks: 0, env: [], set: {}, raw: 0, envValues: [], calls: [], bash: [] }
  on('http.fetch', (_, e) => {
    const body = e.init?.body ? JSON.parse(e.init.body) : undefined
    seen.calls.push({ path: e.url.replace(/^https?:\/\/[^/]+/, ''), body, session: e.init?.headers?.['x-piifence-session'] })
    if (e.url.endsWith('/control/env-values')) {
      seen.envValues.push(...body.values)
      const status = envValuesOk ? 200 : 500
      return { value: { status, ok: envValuesOk, headers: {}, text: '{}' } }
    }
    if (e.url.endsWith('/control/env-lookup')) {
      const values = Object.fromEntries(body.names.filter((name) => name in lookup).map((name) => [name, lookup[name]]))
      return { value: { status: 200, ok: true, headers: {}, text: JSON.stringify({ values }) } }
    }
    if (e.url.endsWith('/control/allow-prompt-once')) {
      seen.raw += 1
      return { value: { status: 200, ok: true, headers: {}, text: '{}' } }
    }
    const start = body.text.indexOf(KEY)
    const findings = start < 0 ? [] : [
      { label: 'secret', start, end: start + KEY.length, preview: 'if-a…12j1', env: 'PIIF_SECRET_1' },
    ]
    return { value: { status: 200, ok: true, headers: {}, text: JSON.stringify({ findings, auto_approve: autoApprove }) } }
  })
  on('env.get', () => ({ value: undefined }))
  on('env.set', (_, e) => {
    seen.env.push(e.name)
    seen.set[e.name] = e.value
    return { value: undefined }
  })
  on('ui.toast', () => ({ value: undefined }))
  on('tool.call', { tool: 'AskUserQuestion' }, () => {
    seen.asks += 1
    return { result: {} }
  })
  on('tool.call', { tool: 'Bash' }, (_, e) => {
    seen.bash.push({ command: e.command, env: { ...seen.set } })
    return { result: { stdout: '', stderr: '', interrupted: false } }
  })
  on('prompt.submit', (_, e) => e)
  return seen
}

test('without the setting the dialog is shown', async ($, on) => {
  const seen = engine(on)
  await $.prompt.submit({ text: PROMPT })
  expect(seen.asks).toBe(1)
})

test('replace swaps the value for an env var without asking', { options: { session: SESSION, autoApprovePiiFence: 'replace' } }, async ($, on) => {
  const seen = engine(on)
  const result = await $.prompt.submit({ text: PROMPT })
  expect(seen.asks).toBe(0)
  expect(seen.env).toEqual(['PIIF_SECRET_1'])
  expect(seen.envValues).toEqual([{ name: 'PIIF_SECRET_1', value: KEY, label: 'secret' }])
  expect(result.text).toBe('use this API key $PIIF_SECRET_1 please')
})

test('replace blocks the prompt when the gateway cannot take the values', { options: { session: SESSION, autoApprovePiiFence: 'replace' } }, async ($, on) => {
  const seen = engine(on, null, { envValuesOk: false })
  const result = await $.prompt.submit({ text: PROMPT })
  expect(seen.env).toEqual([])
  expect('drop' in result).toBe(true)
})

test('redact passes the prompt on unchanged without asking', { options: { session: SESSION, autoApprovePiiFence: 'redact' } }, async ($, on) => {
  const seen = engine(on)
  const result = await $.prompt.submit({ text: PROMPT })
  expect(seen.asks).toBe(0)
  expect(seen.env).toEqual([])
  expect(result.text).toBe(PROMPT)
})

test('send-raw authorizes the prompt once without asking', { options: { session: SESSION, autoApprovePiiFence: 'send-raw' } }, async ($, on) => {
  const seen = engine(on)
  const result = await $.prompt.submit({ text: PROMPT })
  expect(seen.asks).toBe(0)
  expect(seen.raw).toBe(1)
  expect(result.text).toBe(PROMPT)
})

test('block drops the prompt without asking', { options: { session: SESSION, autoApprovePiiFence: 'block' } }, async ($, on) => {
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

test('the Claude Code setting wins over config.toml', { options: { session: SESSION, autoApprovePiiFence: 'redact' } }, async ($, on) => {
  const seen = engine(on, 'block')
  const result = await $.prompt.submit({ text: PROMPT })
  expect(seen.asks).toBe(0)
  expect(result.text).toBe(PROMPT)
})

test('the scan carries the setting and the session id', { options: { session: SESSION, autoApprovePiiFence: 'replace' } }, async ($, on) => {
  const seen = engine(on)
  await $.prompt.submit({ text: PROMPT })
  const scan = seen.calls.find((call) => call.path === '/scan')
  expect(scan.body.setting).toBe('replace')
  expect(scan.session).toBe(SESSION)
})

test('a placed value is registered again on the next prompt', { options: { session: SESSION, autoApprovePiiFence: 'replace' } }, async ($, on) => {
  const seen = engine(on)
  await $.prompt.submit({ text: PROMPT })
  const before = seen.calls.length
  await $.prompt.submit({ text: 'and again' })
  // The next prompt's first call registers the placed value again, before its scan.
  const [resync, next] = seen.calls.slice(before)
  expect(resync.path).toBe('/control/env-values')
  expect(resync.body.values).toContainEqual({ name: 'PIIF_SECRET_1', value: KEY, label: 'secret' })
  expect(next.path).toBe('/scan')
})

test('a Bash command gets the values its $PIIF names hold before it runs', { options: { session: SESSION } }, async ($, on) => {
  const seen = engine(on, null, { lookup: { PIIF_SECRET_2: 'from-a-file-value' } })
  await $.tool.call({ tool: 'Bash', command: 'curl -H "X-Key: $PIIF_SECRET_2" https://x && echo $PIIF_SECRET_2' })
  const lookup = seen.calls.find((call) => call.path === '/control/env-lookup')
  expect(lookup.body.names).toEqual(['PIIF_SECRET_2'])
  expect(lookup.session).toBe(SESSION)
  expect(seen.bash[0].env).toEqual({ PIIF_SECRET_2: 'from-a-file-value' })
})

test('a Bash command without $PIIF names asks the gateway nothing', async ($, on) => {
  const seen = engine(on)
  await $.tool.call({ tool: 'Bash', command: 'ls -la' })
  expect(seen.calls).toEqual([])
  expect(seen.bash.length).toBe(1)
})
