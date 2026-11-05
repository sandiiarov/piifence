import { expect, test } from 'claude-code/testing'

const KEY = 'if-ajsdlk231lj12kl12j1'
const PROMPT = `use this API key ${KEY} please`

const SESSION = '0123456789abcdef0123456789abcdef'
// What `piifence claude` passes the mod.
const OPTIONS = { options: { session: SESSION, gatewayUrl: 'http://127.0.0.1:7788' } }

// Stands for the gateway and the engine: /scan finds the key and names it `env` (null for no name), env.set succeeds, and every toast and AskUserQuestion dialog is counted. Values sent to /control/env-values are recorded; `envValuesOk: false` makes that call fail. /control/env-lookup answers from `lookup`. Every gateway call is recorded with its body and session header.
function engine(on, { env = 'PIIF_SECRET_1', envValuesOk = true, lookup = {} } = {}) {
  const seen = { asks: 0, toasts: [], env: [], set: {}, envValues: [], calls: [], bash: [] }
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
    const start = body.text.indexOf(KEY)
    const findings = start < 0 ? [] : [
      { label: 'secret', start, end: start + KEY.length, preview: 'if-a…12j1', ...(env ? { env } : {}) },
    ]
    return { value: { status: 200, ok: true, headers: {}, text: JSON.stringify({ findings }) } }
  })
  on('env.set', (_, e) => {
    seen.env.push(e.name)
    seen.set[e.name] = e.value
    return { value: undefined }
  })
  on('ui.toast', (_, e) => {
    seen.toasts.push(e.message ?? e.text ?? JSON.stringify(e))
    return { value: undefined }
  })
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

test('a sensitive value becomes an env var without asking, and a toast says so', OPTIONS, async ($, on) => {
  const seen = engine(on)
  const result = await $.prompt.submit({ text: PROMPT })
  expect(seen.asks).toBe(0)
  expect(seen.env).toEqual(['PIIF_SECRET_1'])
  expect(seen.set.PIIF_SECRET_1).toBe(KEY)
  expect(seen.envValues).toEqual([{ name: 'PIIF_SECRET_1', value: KEY, label: 'secret' }])
  expect(result.text).toBe('use this API key $PIIF_SECRET_1 please')
  expect(seen.toasts.length).toBe(1)
  expect(seen.toasts[0]).toContain('$PIIF_SECRET_1')
  expect(seen.toasts[0]).not.toContain(KEY)
})

test('a prompt without sensitive values is left alone', OPTIONS, async ($, on) => {
  const seen = engine(on)
  const result = await $.prompt.submit({ text: 'hello' })
  expect(result.text).toBe('hello')
  expect(seen.toasts).toEqual([])
  expect(seen.env).toEqual([])
})

test('the prompt is blocked when the gateway cannot take the values', OPTIONS, async ($, on) => {
  const seen = engine(on, { envValuesOk: false })
  const result = await $.prompt.submit({ text: PROMPT })
  expect(seen.env).toEqual([])
  expect('drop' in result).toBe(true)
})

test('a value with no variable is left to the gateway placeholder', OPTIONS, async ($, on) => {
  const seen = engine(on, { env: null })
  const result = await $.prompt.submit({ text: PROMPT })
  expect(result.text).toBe(PROMPT)
  expect(seen.env).toEqual([])
  expect(seen.envValues).toEqual([])
  expect(seen.toasts[0]).toContain('placeholder')
})

test('the scan carries the session id', OPTIONS, async ($, on) => {
  const seen = engine(on)
  await $.prompt.submit({ text: PROMPT })
  const scan = seen.calls.find((call) => call.path === '/scan')
  expect(scan.body).toEqual({ text: PROMPT })
  expect(scan.session).toBe(SESSION)
})

test('a placed value is registered again on the next prompt', OPTIONS, async ($, on) => {
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

test('a Bash command gets the values its $PIIF names hold before it runs', OPTIONS, async ($, on) => {
  const seen = engine(on, { lookup: { PIIF_SECRET_2: 'from-a-file-value' } })
  await $.tool.call({ tool: 'Bash', command: 'curl -H "X-Key: $PIIF_SECRET_2" https://x && echo $PIIF_SECRET_2' })
  const lookup = seen.calls.find((call) => call.path === '/control/env-lookup')
  expect(lookup.body.names).toEqual(['PIIF_SECRET_2'])
  expect(lookup.session).toBe(SESSION)
  expect(seen.bash[0].env).toEqual({ PIIF_SECRET_2: 'from-a-file-value' })
})

test('a Bash command without $PIIF names asks the gateway nothing', OPTIONS, async ($, on) => {
  const seen = engine(on)
  await $.tool.call({ tool: 'Bash', command: 'ls -la' })
  expect(seen.calls).toEqual([])
  expect(seen.bash.length).toBe(1)
})

test('outside a piifence claude session the mod does nothing', async ($, on) => {
  const seen = engine(on)
  const result = await $.prompt.submit({ text: PROMPT })
  await $.tool.call({ tool: 'Bash', command: 'echo $PIIF_SECRET_1' })
  expect(result.text).toBe(PROMPT)
  expect(seen.calls).toEqual([])
})
