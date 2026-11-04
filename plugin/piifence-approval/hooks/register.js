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

const DEFAULT_GATEWAY = 'http://127.0.0.1:7788'
const ENV_LIMIT = 4

const ENV_CATEGORY = {
  secret: 'SECRET',
  private_email: 'EMAIL',
  private_person: 'PERSON',
  private_phone: 'PHONE',
  private_address: 'ADDRESS',
  private_url: 'URL',
  private_date: 'DATE',
  account_number: 'ACCOUNT',
}

const envCounters = {
  SECRET: 0,
  EMAIL: 0,
  PERSON: 0,
  PHONE: 0,
  ADDRESS: 0,
  URL: 0,
  DATE: 0,
  ACCOUNT: 0,
}

function gatewayUrl($) {
  try {
    const configured = $.env.get('PIIF_GATEWAY_URL')
    if (configured) return configured.replace(/\/+$/, '')
  } catch {
    // env is unavailable; use the default
  }
  return DEFAULT_GATEWAY
}

async function scan($, text) {
  const response = await $.http.fetch(gatewayUrl($) + '/scan', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ text }),
  })
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

// $.env.set needs the name as a string literal, so the variables are unrolled.
function envSetters($) {
  return {
    SECRET: [
      (value) => $.env.set('PIIF_SECRET_1', value),
      (value) => $.env.set('PIIF_SECRET_2', value),
      (value) => $.env.set('PIIF_SECRET_3', value),
      (value) => $.env.set('PIIF_SECRET_4', value),
    ],
    EMAIL: [
      (value) => $.env.set('PIIF_EMAIL_1', value),
      (value) => $.env.set('PIIF_EMAIL_2', value),
      (value) => $.env.set('PIIF_EMAIL_3', value),
      (value) => $.env.set('PIIF_EMAIL_4', value),
    ],
    PERSON: [
      (value) => $.env.set('PIIF_PERSON_1', value),
      (value) => $.env.set('PIIF_PERSON_2', value),
      (value) => $.env.set('PIIF_PERSON_3', value),
      (value) => $.env.set('PIIF_PERSON_4', value),
    ],
    PHONE: [
      (value) => $.env.set('PIIF_PHONE_1', value),
      (value) => $.env.set('PIIF_PHONE_2', value),
      (value) => $.env.set('PIIF_PHONE_3', value),
      (value) => $.env.set('PIIF_PHONE_4', value),
    ],
    ADDRESS: [
      (value) => $.env.set('PIIF_ADDRESS_1', value),
      (value) => $.env.set('PIIF_ADDRESS_2', value),
      (value) => $.env.set('PIIF_ADDRESS_3', value),
      (value) => $.env.set('PIIF_ADDRESS_4', value),
    ],
    URL: [
      (value) => $.env.set('PIIF_URL_1', value),
      (value) => $.env.set('PIIF_URL_2', value),
      (value) => $.env.set('PIIF_URL_3', value),
      (value) => $.env.set('PIIF_URL_4', value),
    ],
    DATE: [
      (value) => $.env.set('PIIF_DATE_1', value),
      (value) => $.env.set('PIIF_DATE_2', value),
      (value) => $.env.set('PIIF_DATE_3', value),
      (value) => $.env.set('PIIF_DATE_4', value),
    ],
    ACCOUNT: [
      (value) => $.env.set('PIIF_ACCOUNT_1', value),
      (value) => $.env.set('PIIF_ACCOUNT_2', value),
      (value) => $.env.set('PIIF_ACCOUNT_3', value),
      (value) => $.env.set('PIIF_ACCOUNT_4', value),
    ],
  }
}

function planEnvironment(findings) {
  const counters = { ...envCounters }
  const slots = []
  for (const finding of findings) {
    const category = ENV_CATEGORY[finding.label]
    if (!category) return null
    counters[category] += 1
    if (counters[category] > ENV_LIMIT) return null
    slots.push({
      finding,
      category,
      index: counters[category],
      env: `PIIF_${category}_${counters[category]}`,
    })
  }
  return { slots, counters }
}

function rewriteText(text, slots) {
  let rewritten = text
  for (const slot of [...slots].sort((a, b) => b.finding.start - a.finding.start)) {
    rewritten =
      rewritten.slice(0, slot.finding.start) + '$' + slot.env + rewritten.slice(slot.finding.end)
  }
  return rewritten
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

  on('prompt.submit', async ($, e, next) => {
    let scanned
    try {
      scanned = await scan($, e.text)
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
        const response = await $.http.fetch(gatewayUrl($) + '/control/allow-prompt-once', {
          method: 'POST',
        })
        if (!response.ok) throw new Error('gateway rejected allow')
      } catch {
        return { drop: 'piifence: could not authorize raw send; prompt blocked.' }
      }
      return next(e)
    }

    if (choice === 'replace') {
      const setters = envSetters($)
      const values = plan.slots.map((slot) => ({
        name: slot.env,
        value: e.text.slice(slot.finding.start, slot.finding.end),
        label: slot.finding.label,
      }))
      // The gateway replaces these exact values with the variable names in everything sent to the provider, so a command that prints one (`echo $PIIF_SECRET_1`) does not leak it. Without that, the value must not go into the environment.
      try {
        const response = await $.http.fetch(gatewayUrl($) + '/control/env-values', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ values }),
        })
        if (!response.ok) throw new Error('gateway rejected env values')
      } catch {
        return { drop: 'piifence: the gateway could not protect the environment variables; prompt blocked.' }
      }
      try {
        for (const [i, slot] of plan.slots.entries()) {
          await setters[slot.category][slot.index - 1](values[i].value)
        }
      } catch {
        return { drop: 'piifence: could not place the value in the environment; prompt blocked.' }
      }
      Object.assign(envCounters, plan.counters)
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
}
