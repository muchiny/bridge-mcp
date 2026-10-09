// The pure half of the mode-clair plugin: no `$`, no clock, no files.
//
// It turns what the hooks saw (tool calls, skills, plan files, a workflow's
// script and journal, the bridge's answers) into plain state, and that state
// into the French words and pipelines the band, the rows and the pane draw.
// Keeping it pure is what lets every rule here be tested without an engine.

import type {
  BridgeCall,
  CallState,
  ClairState,
  SpStage,
  Step,
  Superpowers,
  TaskRole,
  Workflow,
} from '../types'

export const EMPTY: ClairState = { calls: [] }

/** How many finished bridge calls the state keeps; the oldest go first. */
export const MAX_CALLS = 200

// ---------------------------------------------------------------------------
// Colors
// ---------------------------------------------------------------------------

/** One color per machine, from a palette checked for red-green color blindness. */
export const MACHINE_PALETTE = ['#3987e5', '#d95926', '#199e70'] as const

/** A stable color for a machine name: the same name always gets the same one. */
export function machineColor(host: string): string {
  let hash = 0
  for (const ch of host) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0
  return MACHINE_PALETTE[hash % MACHINE_PALETTE.length] ?? MACHINE_PALETTE[0]
}

// ---------------------------------------------------------------------------
// Recognising a call to the bridge
// ---------------------------------------------------------------------------

/** An MCP tool of a server whose name holds "bridge" (`mcp__bridge-mcp__…`). */
export function isBridgeMcpTool(tool: string): boolean {
  return /^mcp__.*bridge.*__./i.test(tool)
}

/** The bridge's own tool name inside an MCP tool name. */
export function bridgeToolName(tool: string): string {
  const at = tool.lastIndexOf('__')
  return at >= 0 ? tool.slice(at + 2) : tool
}

/** Splits a shell command line into words, honouring single and double quotes. */
export function shellWords(line: string): string[] {
  const words: string[] = []
  let word = ''
  let quote: '"' | "'" | null = null
  let isInWord = false
  for (const ch of line) {
    if (quote) {
      if (ch === quote) quote = null
      else word += ch
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      isInWord = true
      continue
    }
    if (/\s/.test(ch)) {
      if (isInWord) words.push(word)
      word = ''
      isInWord = false
      continue
    }
    word += ch
    isInWord = true
  }
  if (isInWord) words.push(word)
  return words
}

export type CallStart = Pick<BridgeCall, 'tool' | 'via' | 'hosts' | 'command' | 'sudo'>

/**
 * A `bridge-mcp tool <name> key=value …` command line, as the plugin's own
 * bridge skill has Claude run it. Undefined for any other command.
 */
export function parseCliCall(command: string): CallStart | undefined {
  const words = shellWords(command.trim())
  const at = words.findIndex((w, i) => /(^|\/)bridge-mcp$/.test(w) && words[i + 1] === 'tool')
  if (at < 0) return undefined
  const tool = words[at + 2]
  if (!tool || tool.startsWith('-')) return undefined
  const args: Record<string, string> = {}
  for (const w of words.slice(at + 3)) {
    const eq = w.indexOf('=')
    if (eq > 0 && !w.startsWith('-')) args[w.slice(0, eq)] = w.slice(eq + 1)
  }
  return {
    tool,
    via: 'cli',
    hosts: hostsOf(args),
    command: args.command,
    sudo: args.sudo === 'true',
  }
}

/** The arguments of an MCP call to the bridge, read the same way. */
export function parseMcpCall(tool: string, input: Record<string, unknown>): CallStart {
  return {
    tool: bridgeToolName(tool),
    via: 'mcp',
    hosts: hostsOf(input),
    command: typeof input.command === 'string' ? input.command : undefined,
    sudo: input.sudo === true || input.sudo === 'true',
  }
}

function hostsOf(args: Record<string, unknown>): string[] {
  const one = args.host
  if (typeof one === 'string' && one) return [one]
  const many = args.hosts
  if (Array.isArray(many)) return many.filter((h): h is string => typeof h === 'string')
  if (typeof many === 'string' && many) return many.split(',').map(h => h.trim()).filter(Boolean)
  return []
}

// ---------------------------------------------------------------------------
// Classifying what the bridge answered
// ---------------------------------------------------------------------------

export type Outcome = {
  state: CallState
  reason?: string
  summary?: string
}

/**
 * What became of a call, from the bridge's answer as the model read it.
 * The patterns are the bridge's own error texts (src/error.rs) and its
 * `[exit:N]` prefix for a remote command that ran and failed.
 */
export function classify(answer: {
  isError: boolean
  text: string
  readOnly?: boolean
  tool: string
  via: 'mcp' | 'cli'
}): Outcome {
  const text = answer.text ?? ''
  const first = firstLine(text)
  let m: RegExpMatchArray | null
  if (/User declined execution of destructive tool/i.test(text)) {
    return { state: 'declined', reason: 'refusé par toi' }
  }
  if (/Pass --yes|requires confirmation|needs confirmation/i.test(text)) {
    return { state: 'declined', reason: 'non lancé : il faut ton accord' }
  }
  if ((m = text.match(/Command denied:\s*(.+)/i))) {
    return { state: 'denied', reason: clip(m[1] ?? '', 60) }
  }
  if (/Rate limit exceeded for host/i.test(text)) {
    return { state: 'rate-limited', reason: 'plus de 10 requêtes par seconde' }
  }
  if ((m = text.match(/Unknown host:\s*(\S+)/i))) {
    return { state: 'unknown-host', reason: `${m[1]} n'est pas dans ta config` }
  }
  if (/SSH connection failed|SSH authentication failed|SOCKS proxy error|host key (mismatch|unknown)/i.test(text)) {
    return { state: 'unreachable', reason: unreachableReason(text) }
  }
  if ((m = text.match(/SSH command timeout after (\d+)s/i))) {
    return { state: 'failed', reason: `délai dépassé (${m[1]} s)` }
  }
  if ((m = text.match(/^\s*\[exit:(\d+)\]/))) {
    return { state: 'failed', reason: `code ${m[1]}`, summary: firstLine(text.replace(/^\s*\[exit:\d+\]\s*/, '')) }
  }
  if (answer.isError) {
    return { state: 'failed', reason: clip(first || 'erreur', 60) }
  }
  if (/output_id:|\(truncated\)|output stopped at the/i.test(text)) {
    return { state: 'truncated', summary: first }
  }
  return { state: isReadCall(answer) ? 'read' : 'changed', summary: first }
}

/**
 * Whether a call that ran only read. Through MCP the engine says so from the
 * bridge's own annotation (`readOnlyHint`); through the CLI it cannot, since
 * the engine judges the Bash command, so the tool's name decides, and a free
 * command (`ssh_exec`) never counts as a read.
 */
export function isReadCall(answer: { readOnly?: boolean; tool: string; via: 'mcp' | 'cli' }): boolean {
  if (isFreeCommand(answer.tool)) return false
  if (answer.via === 'mcp') return answer.readOnly === true
  return READ_NAME.test(answer.tool)
}

const READ_NAME =
  /_(get|list|ls|status|show|info|query|usage|logs?|tail|describe|search|find|df|du|cat|health|check|metrics|inspect|top|ps|events|version|history|stats|uptime|whoami|diff|read|fetch|facts|inventory|recap)(_|$)/

function unreachableReason(text: string): string {
  if (/authentication failed/i.test(text)) return 'authentification refusée'
  if (/host key/i.test(text)) return 'clé de la machine inconnue ou changée'
  if (/timeout/i.test(text)) return 'pas de réponse (délai SSH)'
  if (/refused/i.test(text)) return 'connexion refusée'
  return 'connexion impossible'
}

/** Tools that run whatever command they are given: the bridge cannot say what changes. */
export function isFreeCommand(tool: string): boolean {
  return /^(ssh_exec|ssh_exec_multi|ssh_session_exec|ssh_win_exec|ssh_powershell)$/.test(tool)
}

function firstLine(text: string): string {
  const line = text.split('\n').map(l => l.trim()).find(l => l && !/^\[exit:/.test(l)) ?? ''
  return clip(line, 70)
}

export function clip(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`
}

// ---------------------------------------------------------------------------
// Words
// ---------------------------------------------------------------------------

/** `0,4 s`, `1 min 12 s`: a duration as the person reads it. */
export function duration(ms: number): string {
  if (ms < 60_000) return `${(Math.max(0, ms) / 1000).toFixed(1).replace('.', ',')} s`
  const min = Math.floor(ms / 60_000)
  const s = Math.round((ms % 60_000) / 1000)
  return s ? `${min} min ${s} s` : `${min} min`
}

export const STATE_WORD: Record<CallState, string> = {
  running: 'en cours',
  you: 'attend ton accord',
  read: 'lecture',
  changed: 'modifié',
  truncated: 'tronqué',
  denied: 'refusé',
  'unknown-host': 'refusé',
  'rate-limited': 'refusé',
  declined: 'non lancé',
  unreachable: 'injoignable',
  failed: 'échec',
}

/** The one-glyph mark of a call's state. */
export function callGlyph(state: CallState): string {
  switch (state) {
    case 'running':
      return '●'
    case 'you':
      return '⚠'
    case 'read':
      return '✓'
    case 'changed':
      return '✎'
    default:
      return '✗'
  }
}

/** Calls that never reached the machine: nothing ran there. */
export function nothingRan(state: CallState): boolean {
  return ['you', 'denied', 'unknown-host', 'rate-limited', 'declined', 'unreachable'].includes(state)
}

/** The fixed trust sentence for a call, or undefined when it ran. */
export function trustSentence(call: BridgeCall): string | undefined {
  const host = call.hosts[0] ?? 'la machine'
  if (nothingRan(call.state)) return `Rien n'est parti vers ${host}.`
  if (call.state === 'failed' && /^code /.test(call.reason ?? '')) {
    return `La commande a tourné sur ${host} et a échoué : elle a pu changer quelque chose.`
  }
  return undefined
}

/** `web-02`, `web-01, web-02`, `web-01 +3`. */
export function hostsLabel(hosts: string[]): string {
  if (hosts.length === 0) return 'aucune machine'
  if (hosts.length <= 2) return hosts.join(', ')
  return `${hosts[0]} +${hosts.length - 1}`
}

/** The headline of a call's row: state, machine, what happened. */
export function callHeadline(call: BridgeCall, now: number): string {
  const host = hostsLabel(call.hosts)
  const who = call.sudo ? ' · root (sudo)' : ''
  switch (call.state) {
    case 'running':
      return `${host}${who} · en cours depuis ${duration(now - call.startedAt)}`
    case 'you':
      return `${host}${who} · attend ton accord`
    case 'read':
      return `${host} · lecture${call.summary ? ` · ${call.summary}` : ''}`
    case 'changed':
      return `${host}${who} · modifié${isFreeCommand(call.tool) ? ' (commande libre)' : ''}`
    case 'truncated':
      return `${host} · tronqué : Claude n'a pas tout lu`
    default:
      return `${host} · ${STATE_WORD[call.state]}${call.reason ? ` · ${call.reason}` : ''}`
  }
}

// ---------------------------------------------------------------------------
// The pipeline of one bridge call
// ---------------------------------------------------------------------------

/**
 * The steps a call goes through inside the bridge, in the bridge's real order
 * today: the destructive gate asks before validation and the blacklist (the
 * known "confirmation before blacklist" defect in CLAUDE.md). Steps the
 * outside cannot see yet stay `next` until the answer says how far it went.
 */
export function bridgeSteps(call: BridgeCall, now: number): Step[] {
  const host = call.hosts[0] ?? 'machine'
  const color = call.hosts[0] ? machineColor(call.hosts[0]) : undefined
  const took = call.endedAt !== undefined ? duration(call.endedAt - call.startedAt) : undefined
  const steps: Step[] = [{ label: 'permission', status: 'done' }]

  if (call.state === 'running') {
    steps.push({ label: 'dans le bridge', status: 'current', detail: duration(now - call.startedAt) })
    steps.push({ label: 'réponse', status: 'next' })
    return steps
  }

  const confirm: Step =
    call.state === 'you'
      ? { label: 'ton accord', status: 'you' }
      : call.state === 'declined'
        ? { label: 'ton accord', status: 'problem', detail: call.reason }
        : call.confirmed
          ? { label: 'ton accord', status: 'done' }
          : call.readOnly
            ? { label: 'accord', status: 'skipped', detail: 'lecture' }
            : { label: 'accord', status: 'skipped' }
  steps.push(confirm)

  const stopped = ['you', 'declined'].includes(call.state)
  const validation: Step = stopped
    ? { label: 'validation', status: 'next' }
    : call.state === 'unknown-host'
      ? { label: 'validation', status: 'problem', detail: 'machine inconnue' }
      : { label: 'validation', status: 'done' }
  steps.push(validation)

  if (call.sudo) {
    steps.push({ label: 'sudo', status: stopped || call.state === 'unknown-host' ? 'next' : 'done' })
  }

  const blacklist: Step = stopped || call.state === 'unknown-host'
    ? { label: 'liste noire', status: 'next' }
    : call.state === 'denied'
      ? { label: 'liste noire', status: 'problem' }
      : call.state === 'rate-limited'
        ? { label: 'limite 10/s', status: 'problem' }
        : { label: 'liste noire', status: 'done' }
  steps.push(blacklist)

  const reached = !nothingRan(call.state) || call.state === 'unreachable'
  const machine: Step = !reached
    ? { label: host, status: 'next', color }
    : call.state === 'unreachable'
      ? { label: host, status: 'problem', detail: 'injoignable' }
      : call.state === 'failed'
        ? { label: host, status: 'problem', detail: call.reason }
        : { label: host, status: 'done', detail: took, color }
  // A machine step that ran well carries the machine's color: the renderer
  // draws it as a colored dot rather than a check, like the mockups.
  steps.push(machine)

  steps.push(
    call.state === 'truncated'
      ? { label: 'réponse', status: 'problem', detail: 'tronquée' }
      : { label: 'réponse', status: 'done' },
  )
  return steps
}

// ---------------------------------------------------------------------------
// Superpowers
// ---------------------------------------------------------------------------

const STAGES: SpStage[] = ['framing', 'spec', 'plan', 'tasks', 'review', 'finish']

export const STAGE_WORD: Record<SpStage, string> = {
  framing: 'cadrage',
  spec: 'spec',
  plan: 'plan',
  tasks: 'tâches',
  review: 'relecture finale',
  finish: 'fin',
}

/** The stage a Superpowers skill moves the session to, if it moves it. */
export function stageOfSkill(skill: string): SpStage | undefined {
  const name = skill.includes(':') ? skill.slice(skill.indexOf(':') + 1) : skill
  switch (name) {
    case 'brainstorming':
      return 'framing'
    case 'writing-plans':
      return 'plan'
    case 'executing-plans':
    case 'subagent-driven-development':
      return 'tasks'
    case 'requesting-code-review':
      return 'review'
    case 'finishing-a-development-branch':
      return 'finish'
    default:
      return undefined
  }
}

/** True for a skill of the Superpowers plugin (`superpowers:…`, or a bare known name). */
export function isSuperpowersSkill(skill: string): boolean {
  return /^superpowers:/i.test(skill) || stageOfSkill(skill) !== undefined
}

export function onSkill(sp: Superpowers | undefined, skill: string): Superpowers | undefined {
  if (!isSuperpowersSkill(skill)) return sp
  const name = skill.includes(':') ? skill.slice(skill.indexOf(':') + 1) : skill
  const next = sp ?? { stage: 'framing' as SpStage, tasks: [], reviewed: [] }
  const stage = stageOfSkill(skill)
  if (!stage) return { ...next, skill: name }
  // A per-task review inside the task loop is not the final review.
  if (stage === 'review' && next.stage === 'tasks' && (next.currentTask ?? 0) < next.tasks.length) {
    return { ...next, skill: name, role: 'review' }
  }
  return { ...next, skill: name, stage: laterStage(next.stage, stage) }
}

function laterStage(a: SpStage, b: SpStage): SpStage {
  return STAGES.indexOf(b) >= STAGES.indexOf(a) || b === 'framing' ? b : a
}

/** A Write the hooks saw: a spec or a plan of Superpowers changes the stage. */
export function onWrite(sp: Superpowers | undefined, path: string, content: string): Superpowers | undefined {
  if (/docs\/superpowers\/specs\/[^/]+\.md$/.test(path)) {
    const base = sp ?? { stage: 'framing' as SpStage, tasks: [], reviewed: [] }
    return { ...base, stage: laterStage(base.stage, 'spec') }
  }
  if (/docs\/superpowers\/plans\/[^/]+\.md$/.test(path)) {
    const base = sp ?? { stage: 'plan' as SpStage, tasks: [], reviewed: [] }
    const plan = parsePlan(content)
    return {
      ...base,
      stage: laterStage(base.stage, 'plan'),
      planPath: path,
      planTitle: plan.title ?? base.planTitle,
      tasks: plan.tasks.length ? plan.tasks : base.tasks,
    }
  }
  return sp
}

/** The title and task titles of a Superpowers plan (`### Task 3: …`). */
export function parsePlan(markdown: string): { title?: string; tasks: string[] } {
  const lines = markdown.split('\n')
  const titleLine = lines.find(l => /^#\s+\S/.test(l))
  const title = titleLine?.replace(/^#\s+/, '').replace(/\s+Implementation Plan$/i, '').trim()
  const tasks: string[] = []
  for (const line of lines) {
    const m = line.match(/^#{2,4}\s+(?:Task|Tâche)\s+(\d+)\s*[:.—–-]?\s*(.*)$/i)
    if (m) tasks[Number(m[1]) - 1] = (m[2] ?? '').trim() || `Tâche ${m[1]}`
  }
  return { title, tasks: Array.from(tasks, (t, i) => t ?? `Tâche ${i + 1}`) }
}

/** The task number and role an Agent call of Superpowers works on. */
export function readAgentCall(description: string, prompt: string): { task?: number; role: TaskRole } {
  const text = `${description}\n${prompt.slice(0, 2000)}`
  const m = text.match(/\b(?:Task|Tâche)\s+(\d+)/i)
  const task = m ? Number(m[1]) : undefined
  const isReview = /review|relecture|relire|reviewer|relit/i.test(description)
  const isFix = /\bfix|corrig/i.test(description)
  return { task, role: isReview ? 'review' : isFix ? 'fix' : 'code' }
}

export function onAgent(sp: Superpowers | undefined, description: string, prompt: string): Superpowers | undefined {
  if (!sp) return sp
  if (sp.stage !== 'tasks' && sp.stage !== 'plan') return sp
  const { task, role } = readAgentCall(description, prompt)
  if (task === undefined) return sp
  const reviewed = role === 'review' && !sp.reviewed.includes(task) ? [...sp.reviewed, task] : sp.reviewed
  const effectiveRole: TaskRole = role === 'code' && sp.reviewed.includes(task) ? 'fix' : role
  return { ...sp, stage: 'tasks', currentTask: task, role: effectiveRole, reviewed }
}

/** The stages of a Superpowers session as one pipeline. */
export function spSteps(sp: Superpowers): Step[] {
  const at = STAGES.indexOf(sp.stage)
  return STAGES.map((stage, i) => {
    const label =
      stage !== 'tasks'
        ? STAGE_WORD[stage]
        : sp.tasks.length
          ? `tâches ${sp.currentTask ?? 0} sur ${sp.tasks.length}`
          : sp.currentTask
            ? `tâche ${sp.currentTask}`
            : STAGE_WORD[stage]
    return { label, status: i < at ? 'done' : i === at ? 'current' : 'next' }
  })
}

/** The loop inside the task in progress: code, review, fix. */
export function taskSteps(sp: Superpowers): Step[] {
  const role = sp.role ?? 'code'
  const order: TaskRole[] = ['code', 'review', 'fix']
  const at = order.indexOf(role)
  const words: Record<TaskRole, string> = {
    code: 'coder (test d’abord)',
    review: 'relire (un autre agent)',
    fix: 'corriger',
  }
  return order.map((r, i) => ({
    label: r === 'fix' && role !== 'fix' ? 'corriger si besoin' : words[r],
    status: i < at ? 'done' : i === at ? 'current' : 'next',
  }))
}

/** `tâche 3 « Écrire le fichier CSV »`. */
export function taskTitle(sp: Superpowers): string | undefined {
  if (!sp.currentTask) return undefined
  const title = sp.tasks[sp.currentTask - 1]
  return title ? `tâche ${sp.currentTask} « ${title} »` : `tâche ${sp.currentTask}`
}

/** Why the step in progress happens, in one sentence. */
export function spWhy(sp: Superpowers): string {
  switch (sp.stage) {
    case 'framing':
      return 'comprendre ce que tu veux avant d’écrire du code.'
    case 'spec':
      return 'écrire ce qui a été décidé, pour que tu le valides.'
    case 'plan':
      return 'découper le travail en petites tâches vérifiables.'
    case 'tasks':
      if (sp.role === 'review') return 'un agent qui n’a pas écrit le code vérifie la tâche.'
      if (sp.role === 'fix') return 'la relecture a trouvé quelque chose à corriger.'
      return 'test d’abord : il doit échouer, puis passer.'
    case 'review':
      return 'relire toute la branche avant de la proposer.'
    case 'finish':
      return 'rien ne quitte ta machine sans ta décision.'
  }
}

// ---------------------------------------------------------------------------
// Workflows (ultracode)
// ---------------------------------------------------------------------------

/** `meta.name`, `meta.description` and the phase titles of a workflow script. */
export function parseWorkflowMeta(script: string): { name?: string; goal?: string; phases: string[] } {
  const start = script.search(/export\s+const\s+meta\s*=\s*\{/)
  if (start < 0) return { phases: [] }
  const open = script.indexOf('{', start)
  let depth = 0
  let end = open
  for (let i = open; i < script.length; i++) {
    const ch = script[i]
    if (ch === '{') depth++
    else if (ch === '}') {
      depth--
      if (depth === 0) {
        end = i
        break
      }
    }
  }
  const meta = script.slice(open, end + 1)
  const str = (key: string) =>
    meta.match(new RegExp(`\\b${key}\\s*:\\s*(['"\`])((?:\\\\.|(?!\\1).)*)\\1`))?.[2]
  const phasesAt = meta.search(/\bphases\s*:\s*\[/)
  const phases: string[] = []
  if (phasesAt >= 0) {
    const block = meta.slice(phasesAt)
    for (const m of block.matchAll(/\btitle\s*:\s*(['"`])((?:\\.|(?!\1).)*)\1/g)) {
      if (m[2]) phases.push(m[2])
    }
  }
  return { name: str('name'), goal: str('description'), phases }
}

export function newWorkflow(script: string | undefined, nameHint: string | undefined, now: number): Workflow {
  const meta = parseWorkflowMeta(script ?? '')
  return {
    name: meta.name ?? nameHint ?? 'workflow',
    goal: meta.goal,
    phases: meta.phases,
    agents: [],
    startedPhases: [],
    isDone: false,
    startedAt: now,
  }
}

/**
 * Folds a workflow journal (one JSON object per line: `started` with
 * `agentId`, `label`, `phase`; `result` with `agentId`) into the agents and
 * the phases that started. The format is Claude Code's and undocumented:
 * a line that does not parse is skipped, never guessed.
 */
export function foldJournal(wf: Workflow, journal: string): Workflow {
  const agents = new Map(wf.agents.map(a => [a.id, { ...a }]))
  const startedPhases = [...wf.startedPhases]
  for (const line of journal.split('\n')) {
    if (!line.trim()) continue
    let row: Record<string, unknown>
    try {
      row = JSON.parse(line) as Record<string, unknown>
    } catch {
      continue
    }
    const id = typeof row.agentId === 'string' ? row.agentId : undefined
    if (row.type === 'started' && id) {
      const phase = typeof row.phase === 'string' ? row.phase : undefined
      const label = typeof row.label === 'string' ? row.label : undefined
      const known = agents.get(id)
      agents.set(id, { id, label: label ?? known?.label, phase: phase ?? known?.phase, isDone: known?.isDone ?? false, isFailed: known?.isFailed ?? false })
      if (phase && !startedPhases.includes(phase)) startedPhases.push(phase)
    } else if (row.type === 'result' && id) {
      const known = agents.get(id) ?? { id, isDone: false, isFailed: false }
      agents.set(id, { ...known, isDone: true, isFailed: row.result === null })
    }
  }
  return { ...wf, agents: [...agents.values()], startedPhases }
}

/** The phase in progress: the last one that started and still has an agent running. */
export function currentPhase(wf: Workflow): string | undefined {
  for (let i = wf.startedPhases.length - 1; i >= 0; i--) {
    const phase = wf.startedPhases[i]
    if (wf.agents.some(a => a.phase === phase && !a.isDone)) return phase
  }
  return wf.startedPhases.at(-1)
}

/** The phases of a workflow as one pipeline, ending in `fin`. */
export function workflowSteps(wf: Workflow): Step[] {
  const phases = wf.phases.length ? wf.phases : wf.startedPhases
  const current = wf.isDone ? undefined : currentPhase(wf)
  const at = current ? phases.indexOf(current) : wf.isDone ? phases.length : -1
  const steps: Step[] = phases.map((phase, i) => {
    const failed = wf.agents.filter(a => a.phase === phase && a.isFailed).length
    const status = wf.isDone || (at >= 0 && i < at) ? 'done' : i === at ? 'current' : 'next'
    return { label: phase, status: failed && status !== 'next' ? 'problem' : status, detail: failed ? `${failed} en échec` : undefined }
  })
  steps.push({ label: 'fin', status: wf.isDone ? 'done' : 'next' })
  return steps
}

/** `2 agents en cours · 5 finis` for the phase in progress, from the journal. */
export function phaseLine(wf: Workflow): string | undefined {
  const phase = currentPhase(wf)
  if (!phase) return undefined
  const mine = wf.agents.filter(a => a.phase === phase)
  const running = mine.filter(a => !a.isDone).length
  const done = mine.filter(a => a.isDone && !a.isFailed).length
  const failed = mine.filter(a => a.isFailed).length
  const parts = [`${running} agent${running > 1 ? 's' : ''} en cours`]
  if (done) parts.push(`${done} fini${done > 1 ? 's' : ''}`)
  if (failed) parts.push(`${failed} sans résultat`)
  return `« ${phase} » : ${parts.join(' · ')}`
}

/** True when a delivered message says this workflow's background task ended. */
export function isWorkflowDoneNotice(text: string, taskId: string | undefined): boolean {
  if (!taskId) return false
  return text.includes(`<task-id>${taskId}</task-id>`) && /<status>(completed|failed|killed)<\/status>/.test(text)
}

// ---------------------------------------------------------------------------
// The state as a whole
// ---------------------------------------------------------------------------

export function addCall(state: ClairState, call: BridgeCall): ClairState {
  const calls = [...state.calls, call]
  const extra = calls.length - MAX_CALLS
  return { ...state, calls: extra > 0 ? calls.slice(extra) : calls }
}

export function patchCall(state: ClairState, id: string, patch: Partial<BridgeCall>): ClairState {
  return { ...state, calls: state.calls.map(c => (c.id === id ? { ...c, ...patch } : c)) }
}

/** The calls that wait on the person. */
export function waitingCalls(state: ClairState): BridgeCall[] {
  return state.calls.filter(c => c.state === 'you')
}

/** The last call made on each machine, in the order machines were first seen. */
export function machines(state: ClairState): { host: string; last: BridgeCall; count: number; changed: number }[] {
  const byHost = new Map<string, { host: string; last: BridgeCall; count: number; changed: number }>()
  for (const call of state.calls) {
    for (const host of call.hosts) {
      const known = byHost.get(host)
      const changed = (known?.changed ?? 0) + (call.state === 'changed' ? 1 : 0)
      byHost.set(host, { host, last: call, count: (known?.count ?? 0) + 1, changed })
    }
  }
  return [...byHost.values()]
}

/** Problems worth a look: refusals, unreachable machines, failures, truncations. */
export function problems(state: ClairState): BridgeCall[] {
  return state.calls.filter(c => !['running', 'you', 'read', 'changed'].includes(c.state))
}

/** The one line the status line shows, or undefined when nothing happened. */
export function statusLine(state: ClairState): string | undefined {
  const waiting = waitingCalls(state)
  if (waiting.length) return `clair · ⚠ ${hostsLabel(waiting[0]?.hosts ?? [])} attend ton accord`
  if (state.workflow && !state.workflow.isDone) {
    const phase = currentPhase(state.workflow)
    return `clair · ${state.workflow.name}${phase ? ` · ${phase}` : ''} · rien pour toi`
  }
  const sp = state.superpowers
  if (sp && sp.stage !== 'finish') {
    const task = sp.stage === 'tasks' && sp.currentTask ? `tâche ${sp.currentTask} sur ${sp.tasks.length || '?'}` : STAGE_WORD[sp.stage]
    return `clair · ${task} · rien pour toi`
  }
  if (!state.calls.length) return undefined
  const hosts = machines(state).length
  const changed = state.calls.filter(c => c.state === 'changed').length
  const bad = problems(state).length
  const parts = [`${hosts} machine${hosts > 1 ? 's' : ''}`]
  if (changed) parts.push(`✎ ${changed}`)
  if (bad) parts.push(`✗ ${bad}`)
  return `clair · ${parts.join(' · ')}`
}
