import type { EngineInterface, Register } from 'claude-code'

const NAME = /\$\{(PIIF_SECRET_\d+)\}|\$(PIIF_SECRET_\d+)/g
const EXPORT = /^export (PIIF_SECRET_\d+)='((?:[^']|'\\'')*)'$/gm
const RELOAD_AFTER_MS = 2000

let values = new Map<string, string>()
let loadedAt = -Infinity
let loading: Promise<void> | undefined

export function parseExports(stdout: string): Map<string, string> {
  const found = new Map<string, string>()
  for (const [, name, quoted] of stdout.matchAll(EXPORT)) {
    if (name !== undefined && quoted !== undefined) found.set(name, quoted.replaceAll("'\\''", "'"))
  }
  return found
}

export function namesIn(text: string): string[] {
  return [...text.matchAll(NAME)].flatMap(([, braced, bare]) => braced ?? bare ?? [])
}

export function reveal(text: string, known: ReadonlyMap<string, string>): string {
  return text.replace(NAME, (whole, braced, bare) => known.get(braced ?? bare) ?? whole)
}

export function revealDeep(value: unknown, known: ReadonlyMap<string, string>): unknown {
  if (typeof value === 'string') return reveal(value, known)
  if (Array.isArray(value)) return value.map(item => revealDeep(item, known))
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, revealDeep(item, known)]),
    )
  }
  return value
}

export function sessionOf(
  headers: string | undefined,
  baseUrl: string | undefined,
): { id: string; port: string } | undefined {
  const id = headers
    ?.split('\n')
    .map(line => line.split(':'))
    .find(([name]) => name?.trim().toLowerCase() === 'x-piifence-session')?.[1]
    ?.trim()
  const port = baseUrl?.replace(/\/$/, '').match(/^http:\/\/127\.0\.0\.1:(\d+)$/)?.[1]
  return id && /^[0-9a-f]{32}$/i.test(id) && port ? { id, port } : undefined
}

async function load($: EngineInterface): Promise<void> {
  if ((await $.env.get('PIIF_REVEAL')) === 'off') return
  const session = sessionOf(
    await $.env.get('ANTHROPIC_CUSTOM_HEADERS'),
    await $.env.get('ANTHROPIC_BASE_URL'),
  )
  if (!session) return
  const run = await $.process.run(['piifence', 'env', session.id, session.port], {
    timeoutMs: 5000,
  })
  if (run.exitCode === 0) values = parseExports(run.stdout)
}

async function valuesFor($: EngineInterface, text: string): Promise<Map<string, string> | undefined> {
  const names = namesIn(text)
  if (names.length === 0) return undefined
  const now = await $.clock.now()
  if (names.some(name => !values.has(name)) && now - loadedAt > RELOAD_AFTER_MS) {
    loadedAt = now
    loading ??= load($).finally(() => {
      loading = undefined
    })
  }
  await loading
  return values
}

export const register: Register = on => {
  on('ui.render', { component: 'AssistantMessage' }, async ($, e, next) => {
    const known = await valuesFor($, e.props.text)
    return known ? next({ ...e, props: { ...e.props, text: reveal(e.props.text, known) } }) : next(e)
  })

  on('ui.render', { component: 'ToolUse' }, async ($, e, next) => {
    const known = await valuesFor($, JSON.stringify(e.props.input) ?? '')
    return known ? next({ ...e, props: { ...e.props, input: revealDeep(e.props.input, known) } }) : next(e)
  })
}
