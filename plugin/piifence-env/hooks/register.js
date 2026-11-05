// piifence mod: replace sensitive values in prompts with environment variables.
//
// A sensitive value in a prompt becomes `$PIIF_<CATEGORY>_<N>`, an environment variable available to local Bash commands, so the agent can use it without the provider ever seeing it. A toast lists what was replaced. Nothing is asked.
//
// The gateway does the same to values it finds in tool output and files. The mod fetches such a value from the gateway just before a Bash command that names it runs.
//
// When a value cannot get a variable (more than 9 in a category, or a label with no variables), the gateway replaces it with a placeholder instead.
//
// It only runs in a `piifence claude` session, which passes the session id and the gateway URL as plugin options. Without them it registers no hooks.

// A name the gateway can hand out; it numbers 1 to 9 per category (its ENV_LIMIT).
const ENV_NAME = /\bPIIF_(?:SECRET|EMAIL|PERSON|PHONE|ADDRESS|URL|DATE|ACCOUNT)_[1-9]\b/g

// Values this mod put into the environment, by name, so it can register them again if the gateway restarts. Memory only.
const placed = new Map()

// The gateway `piifence claude` started for this session, as the `gatewayUrl` plugin option (the engine does not hand the mod the process environment).
let gatewayBase = ''

// The session id `piifence claude` gives this session, as the `session` plugin option; the gateway keys this session's values on it. It comes as an option, not from the environment, because the engine refuses a request that carries an environment value.
let sessionId = ''

function post($, path, body) {
  return $.http.fetch(gatewayBase + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-piifence-session': sessionId },
    body: JSON.stringify(body),
  })
}

async function scan($, text) {
  const response = await post($, '/scan', { text })
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

function rewriteText(text, slots) {
  let rewritten = text
  for (const slot of [...slots].sort((a, b) => b.start - a.start)) {
    rewritten = rewritten.slice(0, slot.start) + '$' + slot.env + rewritten.slice(slot.end)
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

function tell($, text) {
  try {
    $.ui.toast(text)
  } catch {
    // No surface to show it on; the gateway notice still reports redactions.
  }
}

// What `$PIIF_…` names are, attached to the session's first prompt. Without it the agent meets a name in tool output with no idea what it is: it guesses something redacted its output, warns that a secret leaked, and does not know it can use the name. (A system prompt section would be the natural place, but an organization's policy plugin may skip user plugins' `prompt.compose` hooks.)
export const VARIABLES_NOTE = [
  '# piifence environment variables',
  '',
  'This session runs through piifence, which keeps secrets and personal data from reaching you. Before anything is sent to you (the user\'s prompts, command output, file contents), piifence replaces each sensitive value with an environment variable name such as `$PIIF_SECRET_1` or `$PIIF_EMAIL_2`. The real value stays on the user\'s machine.',
  '',
  '- Use the name in Bash commands, quoted, where you would use the value: `curl -H "Authorization: Bearer $PIIF_SECRET_1" …`. piifence sets the variable just before the command runs, so it expands to the real value.',
  '- A value you see as a `$PIIF_…` name was not exposed to you or the provider. Do not warn that it leaked or suggest rotating it on that account.',
  '- Do not try to print, decode or otherwise reveal the values; whatever a command prints comes back to you as the name again.',
  '- A placeholder such as `<secret_3>` stands for a value piifence could not give a name; it cannot be used in commands.',
].join('\n')

// Whether this session's agent has been sent VARIABLES_NOTE. Module state, so a reload of the mod sends it again.
let explained = false

function list(lines) {
  const shown = lines.slice(0, 6).map((line) => `  ${line}`).join('\n')
  return lines.length > 6 ? `${shown}\n  … and ${lines.length - 6} more` : shown
}

export function register(on, options) {
  if (!/^[0-9a-f]{32}$/.test(options?.session ?? '')) return
  if (!/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(options?.gatewayUrl ?? '')) return
  sessionId = options.session
  gatewayBase = options.gatewayUrl
  explained = false

  on('prompt.submit', async ($, e, nextHook) => {
    // Every way this prompt goes on attaches VARIABLES_NOTE the first time.
    const next = (prompt) => {
      if (explained) return nextHook(prompt)
      explained = true
      return nextHook({ ...prompt, context: [...(prompt.context ?? []), VARIABLES_NOTE] })
    }

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

    let findings
    try {
      findings = await scan($, e.text)
    } catch {
      // Gateway unreachable: leave the prompt alone; the gateway will redact
      // when it comes back (or the request fails closed).
      return next(e)
    }
    if (findings.length === 0) return next(e)

    // The gateway names each finding (`env`); one without a name (over the limit, or a label with no variables) is left for the gateway to replace with a placeholder.
    const slots = findings.filter((finding) => typeof finding.env === 'string')
    const rest = findings.filter((finding) => typeof finding.env !== 'string')
    const values = slots.map((slot) => ({
      name: slot.env,
      value: e.text.slice(slot.start, slot.end),
      label: slot.label,
    }))

    if (values.length > 0) {
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
    }

    const lines = [
      ...slots.map((slot) => `${slot.label} ${slot.preview} → $${slot.env}`),
      ...rest.map((finding) => `${finding.label} ${finding.preview} → placeholder`),
    ]
    tell($, `piifence replaced ${findings.length} sensitive value(s) in your prompt:\n${list(lines)}`)

    if (slots.length === 0) return next(e)
    const mapping = slots.map((slot) => `${slot.label} ${slot.preview} → $${slot.env}`).join(', ')
    const note = `piifence: sensitive values were replaced with environment variables available to local Bash commands (${mapping}). Use the variable names in commands; do not print their values.`
    return next({
      ...e,
      text: rewriteText(e.text, slots),
      context: [...(e.context ?? []), note],
    })
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
