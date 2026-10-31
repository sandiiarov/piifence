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
// Uses Claude Code's native dialog: $.ui.ask.

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
  if (!response.ok) return []
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
  return deduped
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

async function envReplaceText($, text) {
  const findings = await scan($, text)
  if (findings.length === 0) return null
  const plan = planEnvironment(findings)
  if (!plan) return null
  const setters = envSetters($)
  try {
    for (const slot of plan.slots) {
      const value = text.slice(slot.finding.start, slot.finding.end)
      await setters[slot.category][slot.index - 1](value)
    }
  } catch {
    return null
  }
  Object.assign(envCounters, plan.counters)
  return rewriteText(text, plan.slots)
}

export function register(on) {
  on('prompt.submit', async ($, e, next) => {
    let findings = []
    try {
      findings = await scan($, e.text)
    } catch {
      // Gateway unreachable: leave the prompt alone; the gateway will redact
      // when it comes back (or the request fails closed).
      return next(e)
    }
    if (findings.length === 0) return next(e)

    const plan = planEnvironment(findings)
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

    const options = []
    if (plan) {
      options.push(plan.slots.length === 1 ? `Use $${plan.slots[0].env}` : 'Use env vars')
    }
    options.push('Redact', 'Send raw', 'Block')

    let answer
    try {
      answer = await $.ui.ask(
        `piifence detected ${findings.length} sensitive value(s) in this prompt:\n${lines}${more}\n\nWhat should happen before this reaches the provider?`,
        options,
      )
    } catch {
      // Dismissed, or no interactive UI (e.g. claude -p): redact by default.
      return next(e)
    }

    if (answer === 'Block') {
      return { drop: 'piifence: prompt blocked. Remove the sensitive value and resend.' }
    }

    if (answer === 'Send raw') {
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

    if (plan && answer === options[0]) {
      const setters = envSetters($)
      try {
        for (const slot of plan.slots) {
          const value = e.text.slice(slot.finding.start, slot.finding.end)
          await setters[slot.category][slot.index - 1](value)
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

    // Redact (or a typed custom answer): let the gateway replace spans.
    return next(e)
  }).catch(() => {
    // A failing hook must not turn into an unredacted prompt: the gateway still
    // redacts, so let the prompt continue.
  })


  // Instruction files (CLAUDE.md, @imports): the context block is what the
  // model reads, so rewrite it there too instead of leaving a placeholder.
  on('prompt.context', async ($, e, next) => {
    const blocks = []
    let changed = false
    for (const block of e.blocks ?? []) {
      if (block && (block.name === 'claudeMd' || block.name === 'attachedProject')) {
        const text = await envReplaceText($, block.text).catch(() => null)
        if (text !== null) {
          blocks.push({ ...block, text })
          changed = true
          continue
        }
      }
      blocks.push(block)
    }
    if (!changed) return next(e)
    return { blocks }
  }).catch(() => {
    // Leave the context alone; the gateway still redacts it.
  })

  // Tool results and injected rows: replace secrets with env variables too, so
  // the model can use them. The screen may show the raw row before this rewrite;
  // the transcript and the next request see only the variable name.
  on('session.append', async ($, e, next) => {
    if (['prompt', 'response', 'note', 'notice', 'compaction'].includes(e.door)) {
      return next(e)
    }
    const original = e.message.content
    if (typeof original === 'string') {
      const text = await envReplaceText($, original).catch(() => null)
      if (text === null) return next(e)
      return next({ ...e, message: { ...e.message, content: text } })
    }
    if (!Array.isArray(original)) return next(e)

    const rewritten = []
    let changed = false
    for (const block of original) {
      if (!block) {
        rewritten.push(block)
        continue
      }
      if (block.type === 'tool_result') {
        if (typeof block.content === 'string') {
          const text = await envReplaceText($, block.content).catch(() => null)
          if (text !== null) {
            rewritten.push({ ...block, content: text })
            changed = true
          } else {
            rewritten.push(block)
          }
          continue
        }
        if (Array.isArray(block.content)) {
          const inner = []
          for (const item of block.content) {
            if (item && item.type === 'text' && typeof item.text === 'string') {
              const text = await envReplaceText($, item.text).catch(() => null)
              if (text !== null) {
                inner.push({ ...item, text })
                changed = true
                continue
              }
            }
            inner.push(item)
          }
          rewritten.push({ ...block, content: inner })
          continue
        }
        rewritten.push(block)
        continue
      }
      if (block.type === 'text' && typeof block.text === 'string') {
        const text = await envReplaceText($, block.text).catch(() => null)
        if (text !== null) {
          rewritten.push({ ...block, text })
          changed = true
          continue
        }
      }
      rewritten.push(block)
    }
    if (!changed) return next(e)
    return next({ ...e, message: { ...e.message, content: rewritten } })
  }).catch(() => {
    // Leave the row alone; the gateway still replaces the value with a placeholder.
  })

}
