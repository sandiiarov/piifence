// piifence approval mod: ask before a prompt with sensitive values is sent.
//
// Choices:
//   Use $PIIF_<CATEGORY>_<N> — replace the value with an environment variable
//     available to local Bash commands, so the agent can use it without the
//     provider ever seeing it.
//   Redact — the gateway replaces the value with a placeholder.
//   Send raw — the gateway lets this prompt through once (tool results are
//     still scanned and redacted).
//   Block — the prompt returns to the input.
//
// Uses Claude Code's native dialog: $.ui.ask. The `autoApprovePiiFence` setting
// (replace, redact, send-raw, block) skips the dialog and applies that choice to
// every prompt; `ask`, the default, keeps the dialog.
//
// With `replace` in effect (this setting, else config.toml's `auto_approve`), the gateway also turns values it finds in tool output and files into `$PIIF_…` variables. The mod fetches such a value from the gateway just before a Bash command that names it runs.

const DEFAULT_GATEWAY = 'http://127.0.0.1:7788'

// A name the gateway can hand out; it numbers 1 to 9 per category (its ENV_LIMIT).
const ENV_NAME = /\bPIIF_(?:SECRET|EMAIL|PERSON|PHONE|ADDRESS|URL|DATE|ACCOUNT)_[1-9]\b/g

// Values this mod put into the environment, by name, so it can register them again if the gateway restarts. Memory only.
const placed = new Map()

// The gateway `piifence claude` started for this session, as the `gatewayUrl` plugin option (the engine does not hand the mod the process environment).
let gatewayBase = DEFAULT_GATEWAY

function gatewayUrl() {
  return gatewayBase
}

// The session id `piifence claude` gives this session, as the `session` plugin option; the gateway keys this session's values on it. It comes as an option, not from the environment, because the engine refuses a request that carries an environment value.
let sessionId = ''

function gatewayHeaders() {
  const headers = { 'content-type': 'application/json' }
  if (/^[0-9a-f]{32}$/.test(sessionId)) headers['x-piifence-session'] = sessionId
  return headers
}

function post($, path, body) {
  return $.http.fetch(gatewayUrl() + path, {
    method: 'POST',
    headers: gatewayHeaders(),
    body: JSON.stringify(body),
  })
}

async function scan($, text, setting) {
  const response = await post($, '/scan', { text, setting })
  if (!response.ok) return { findings: [], autoApprove: undefined }
  const parsed = JSON.parse(response.text)
  const findings = Array.isArray(parsed.findings) ? parsed.findings : []
  // The gateway can report overlapping model/gitleaks spans for the same value;
  // rewriting both with original offsets corrupts the text. Keep the longest
  // span of each overlapping run.
  const sorted = [...findings].sort(
    (a, b) => a.start - b.start || b.end - b.start - (a.end - a.start),
  )
  const deduped = []
  for (const finding of sorted) {
    const previous = deduped[deduped.length - 1]
    if (previous && finding.start < previous.end) {
      if (finding.end - finding.start > previous.end - previous.start) {
        deduped[deduped.length - 1] = finding
      }
      continue
    }
    deduped.push(finding)
  }
  // `auto_approve` from piifence's own config file, when it sets one.
  return { findings: deduped, autoApprove: parsed.auto_approve ?? undefined }
}

// $.env.set needs the name as a string literal, so every name is unrolled (generated: 8 categories x ENV_LIMIT).
function envSetters($) {
  return {
    PIIF_SECRET_1: (value) => $.env.set('PIIF_SECRET_1', value),
    PIIF_SECRET_2: (value) => $.env.set('PIIF_SECRET_2', value),
    PIIF_SECRET_3: (value) => $.env.set('PIIF_SECRET_3', value),
    PIIF_SECRET_4: (value) => $.env.set('PIIF_SECRET_4', value),
    PIIF_SECRET_5: (value) => $.env.set('PIIF_SECRET_5', value),
    PIIF_SECRET_6: (value) => $.env.set('PIIF_SECRET_6', value),
    PIIF_SECRET_7: (value) => $.env.set('PIIF_SECRET_7', value),
    PIIF_SECRET_8: (value) => $.env.set('PIIF_SECRET_8', value),
    PIIF_SECRET_9: (value) => $.env.set('PIIF_SECRET_9', value),
    PIIF_EMAIL_1: (value) => $.env.set('PIIF_EMAIL_1', value),
    PIIF_EMAIL_2: (value) => $.env.set('PIIF_EMAIL_2', value),
    PIIF_EMAIL_3: (value) => $.env.set('PIIF_EMAIL_3', value),
    PIIF_EMAIL_4: (value) => $.env.set('PIIF_EMAIL_4', value),
    PIIF_EMAIL_5: (value) => $.env.set('PIIF_EMAIL_5', value),
    PIIF_EMAIL_6: (value) => $.env.set('PIIF_EMAIL_6', value),
    PIIF_EMAIL_7: (value) => $.env.set('PIIF_EMAIL_7', value),
    PIIF_EMAIL_8: (value) => $.env.set('PIIF_EMAIL_8', value),
    PIIF_EMAIL_9: (value) => $.env.set('PIIF_EMAIL_9', value),
    PIIF_PERSON_1: (value) => $.env.set('PIIF_PERSON_1', value),
    PIIF_PERSON_2: (value) => $.env.set('PIIF_PERSON_2', value),
    PIIF_PERSON_3: (value) => $.env.set('PIIF_PERSON_3', value),
    PIIF_PERSON_4: (value) => $.env.set('PIIF_PERSON_4', value),
    PIIF_PERSON_5: (value) => $.env.set('PIIF_PERSON_5', value),
    PIIF_PERSON_6: (value) => $.env.set('PIIF_PERSON_6', value),
    PIIF_PERSON_7: (value) => $.env.set('PIIF_PERSON_7', value),
    PIIF_PERSON_8: (value) => $.env.set('PIIF_PERSON_8', value),
    PIIF_PERSON_9: (value) => $.env.set('PIIF_PERSON_9', value),
    PIIF_PHONE_1: (value) => $.env.set('PIIF_PHONE_1', value),
    PIIF_PHONE_2: (value) => $.env.set('PIIF_PHONE_2', value),
    PIIF_PHONE_3: (value) => $.env.set('PIIF_PHONE_3', value),
    PIIF_PHONE_4: (value) => $.env.set('PIIF_PHONE_4', value),
    PIIF_PHONE_5: (value) => $.env.set('PIIF_PHONE_5', value),
    PIIF_PHONE_6: (value) => $.env.set('PIIF_PHONE_6', value),
    PIIF_PHONE_7: (value) => $.env.set('PIIF_PHONE_7', value),
    PIIF_PHONE_8: (value) => $.env.set('PIIF_PHONE_8', value),
    PIIF_PHONE_9: (value) => $.env.set('PIIF_PHONE_9', value),
    PIIF_ADDRESS_1: (value) => $.env.set('PIIF_ADDRESS_1', value),
    PIIF_ADDRESS_2: (value) => $.env.set('PIIF_ADDRESS_2', value),
    PIIF_ADDRESS_3: (value) => $.env.set('PIIF_ADDRESS_3', value),
    PIIF_ADDRESS_4: (value) => $.env.set('PIIF_ADDRESS_4', value),
    PIIF_ADDRESS_5: (value) => $.env.set('PIIF_ADDRESS_5', value),
    PIIF_ADDRESS_6: (value) => $.env.set('PIIF_ADDRESS_6', value),
    PIIF_ADDRESS_7: (value) => $.env.set('PIIF_ADDRESS_7', value),
    PIIF_ADDRESS_8: (value) => $.env.set('PIIF_ADDRESS_8', value),
    PIIF_ADDRESS_9: (value) => $.env.set('PIIF_ADDRESS_9', value),
    PIIF_URL_1: (value) => $.env.set('PIIF_URL_1', value),
    PIIF_URL_2: (value) => $.env.set('PIIF_URL_2', value),
    PIIF_URL_3: (value) => $.env.set('PIIF_URL_3', value),
    PIIF_URL_4: (value) => $.env.set('PIIF_URL_4', value),
    PIIF_URL_5: (value) => $.env.set('PIIF_URL_5', value),
    PIIF_URL_6: (value) => $.env.set('PIIF_URL_6', value),
    PIIF_URL_7: (value) => $.env.set('PIIF_URL_7', value),
    PIIF_URL_8: (value) => $.env.set('PIIF_URL_8', value),
    PIIF_URL_9: (value) => $.env.set('PIIF_URL_9', value),
    PIIF_DATE_1: (value) => $.env.set('PIIF_DATE_1', value),
    PIIF_DATE_2: (value) => $.env.set('PIIF_DATE_2', value),
    PIIF_DATE_3: (value) => $.env.set('PIIF_DATE_3', value),
    PIIF_DATE_4: (value) => $.env.set('PIIF_DATE_4', value),
    PIIF_DATE_5: (value) => $.env.set('PIIF_DATE_5', value),
    PIIF_DATE_6: (value) => $.env.set('PIIF_DATE_6', value),
    PIIF_DATE_7: (value) => $.env.set('PIIF_DATE_7', value),
    PIIF_DATE_8: (value) => $.env.set('PIIF_DATE_8', value),
    PIIF_DATE_9: (value) => $.env.set('PIIF_DATE_9', value),
    PIIF_ACCOUNT_1: (value) => $.env.set('PIIF_ACCOUNT_1', value),
    PIIF_ACCOUNT_2: (value) => $.env.set('PIIF_ACCOUNT_2', value),
    PIIF_ACCOUNT_3: (value) => $.env.set('PIIF_ACCOUNT_3', value),
    PIIF_ACCOUNT_4: (value) => $.env.set('PIIF_ACCOUNT_4', value),
    PIIF_ACCOUNT_5: (value) => $.env.set('PIIF_ACCOUNT_5', value),
    PIIF_ACCOUNT_6: (value) => $.env.set('PIIF_ACCOUNT_6', value),
    PIIF_ACCOUNT_7: (value) => $.env.set('PIIF_ACCOUNT_7', value),
    PIIF_ACCOUNT_8: (value) => $.env.set('PIIF_ACCOUNT_8', value),
    PIIF_ACCOUNT_9: (value) => $.env.set('PIIF_ACCOUNT_9', value),
  }
}

// The variables for a prompt's findings, named by the gateway (`env` on each finding), or null when any finding has no name: over the limit, or a label with no variables.
function planEnvironment(findings) {
  if (!findings.every((finding) => typeof finding.env === 'string')) return null
  return { slots: findings.map((finding) => ({ finding, env: finding.env })) }
}

function rewriteText(text, slots) {
  let rewritten = text
  for (const slot of [...slots].sort((a, b) => b.finding.start - a.finding.start)) {
    rewritten =
      rewritten.slice(0, slot.finding.start) + '$' + slot.env + rewritten.slice(slot.finding.end)
  }
  return rewritten
}

// Put `value` into `$name`; false when the name has no setter.
async function setEnv($, name, value) {
  const setter = envSetters($)[name]
  if (!setter) return false
  await setter(value)
  return true
}

// The choices the dialog offers, as the `autoApprovePiiFence` setting names them.
// `ask` (the default) shows the dialog; any other value applies that choice to
// every prompt without asking.
const CHOICES = ['ask', 'replace', 'redact', 'send-raw', 'block']

export function autoChoice(options) {
  const configured = options?.autoApprovePiiFence
  return CHOICES.includes(configured) ? configured : 'ask'
}

function describe(findings, plan) {
  const lines = findings
    .slice(0, 6)
    .map((finding) => {
      const slot = plan?.slots.find(
        (candidate) =>
          candidate.finding.start === finding.start && candidate.finding.end === finding.end,
      )
      return `  ${finding.label} ${finding.preview}${slot ? ` → $${slot.env}` : ''}`
    })
    .join('\n')
  const more = findings.length > 6 ? `\n  … and ${findings.length - 6} more` : ''
  return `${lines}${more}`
}

async function askChoice($, findings, plan) {
  const options = []
  if (plan) {
    options.push(plan.slots.length === 1 ? `Use $${plan.slots[0].env}` : 'Use env vars')
  }
  options.push('Redact', 'Send raw', 'Block')
  let answer
  try {
    answer = await $.ui.ask(
      `piifence detected ${findings.length} sensitive value(s) in this prompt:\n${describe(findings, plan)}\n\nWhat should happen before this reaches the provider?`,
      options,
    )
  } catch {
    // Dismissed, or no interactive UI (e.g. claude -p): redact by default.
    return 'redact'
  }
  if (plan && answer === options[0]) return 'replace'
  if (answer === 'Send raw') return 'send-raw'
  if (answer === 'Block') return 'block'
  // Redact, or a typed custom answer: let the gateway replace spans.
  return 'redact'
}

function tell($, text) {
  try {
    $.ui.toast(text)
  } catch {
    // No surface to show it on; the gateway notice still reports redactions.
  }
}

export function register(on, options) {
  const auto = autoChoice(options)
  sessionId = typeof options?.session === 'string' ? options.session : ''
  gatewayBase = /^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(options?.gatewayUrl ?? '')
    ? options.gatewayUrl
    : DEFAULT_GATEWAY

  on('prompt.submit', async ($, e, next) => {
    // After a gateway restart it no longer knows the values this mod placed; register them again so their names stay theirs. Best effort: the prompt below registers its own values strictly.
    if (placed.size > 0) {
      try {
        await post($, '/control/env-values', {
          values: [...placed].map(([name, { value, label }]) => ({ name, value, label })),
        })
      } catch {
        // Gateway unreachable; the scan below fails too and leaves redaction to the gateway.
      }
    }

    let scanned
    try {
      // The setting goes along so the gateway applies it to this session's tool output too.
      scanned = await scan($, e.text, auto)
    } catch {
      // Gateway unreachable: leave the prompt alone; the gateway will redact
      // when it comes back (or the request fails closed).
      return next(e)
    }
    const { findings } = scanned
    if (findings.length === 0) return next(e)

    // The Claude Code setting wins; otherwise piifence's config.toml `auto_approve`.
    const fromConfig = autoChoice({ autoApprovePiiFence: scanned.autoApprove })
    const source = auto !== 'ask' ? 'autoApprovePiiFence' : 'auto_approve in config.toml'
    const configured = auto !== 'ask' ? auto : fromConfig

    const plan = planEnvironment(findings)
    let choice = configured === 'ask' ? await askChoice($, findings, plan) : configured
    // Over the variable limit, or a label with no variable: a placeholder instead.
    if (choice === 'replace' && !plan) choice = 'redact'
    if (configured !== 'ask') {
      tell($, `piifence (${choice}, from ${source}): ${findings.length} sensitive value(s)\n${describe(findings, choice === 'replace' ? plan : null)}`)
    }

    if (choice === 'block') {
      return { drop: 'piifence: prompt blocked. Remove the sensitive value and resend.' }
    }

    if (choice === 'send-raw') {
      try {
        const response = await post($, '/control/allow-prompt-once', {})
        if (!response.ok) throw new Error('gateway rejected allow')
      } catch {
        return { drop: 'piifence: could not authorize raw send; prompt blocked.' }
      }
      return next(e)
    }

    if (choice === 'replace') {
      const values = plan.slots.map((slot) => ({
        name: slot.env,
        value: e.text.slice(slot.finding.start, slot.finding.end),
        label: slot.finding.label,
      }))
      // The gateway replaces these exact values with the variable names in everything sent to the provider, so a command that prints one (`echo $PIIF_SECRET_1`) does not leak it. Without that, the value must not go into the environment.
      try {
        const response = await post($, '/control/env-values', { values })
        if (!response.ok) throw new Error('gateway rejected env values')
      } catch {
        return { drop: 'piifence: the gateway could not protect the environment variables; prompt blocked.' }
      }
      try {
        for (const { name, value } of values) {
          if (!(await setEnv($, name, value))) throw new Error(`no setter for ${name}`)
        }
      } catch {
        return { drop: 'piifence: could not place the value in the environment; prompt blocked.' }
      }
      for (const { name, value, label } of values) placed.set(name, { value, label })
      const mapping = plan.slots
        .map((slot) => `${slot.finding.label} ${slot.finding.preview} → $${slot.env}`)
        .join(', ')
      const note = `piifence: sensitive values were replaced with environment variables available to local Bash commands (${mapping}). Use the variable names in commands; do not print their values.`
      return next({
        ...e,
        text: rewriteText(e.text, plan.slots),
        context: [...(e.context ?? []), note],
      })
    }

    // Redact: let the gateway replace spans.
    return next(e)
  }).catch(() => {
    // A failing hook must not turn into an unredacted prompt: the gateway still
    // redacts, so let the prompt continue.
  })

  // A value the gateway found in tool output or a file reaches the agent as `$PIIF_…`, but only the gateway holds it. Fetch the values a command names and set them just before it runs. Each run asks again, so a name the gateway gave a new value after a restart gets that value.
  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    const command = typeof e.command === 'string' ? e.command : ''
    const names = [...new Set(command.match(ENV_NAME) ?? [])]
    if (names.length === 0) return next(e)
    try {
      const response = await post($, '/control/env-lookup', { names })
      if (response.ok) {
        const { values } = JSON.parse(response.text)
        for (const [name, value] of Object.entries(values ?? {})) {
          if (typeof value === 'string') await setEnv($, name, value)
        }
      }
    } catch {
      // Gateway unreachable: run with what the environment already holds.
    }
    return next(e)
  }).catch(() => {
    // Setting a variable failed; the command still runs, without it.
  })
}
