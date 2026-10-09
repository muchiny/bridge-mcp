// mode-clair: one place to look while Superpowers, ultracode workflows and
// bridge-mcp work for you.
//
// The hooks here only observe: every `tool.call` hook calls `next(e)` with
// the input untouched and hands back what it got, and every failure falls
// through to `next`. What they see goes into one value in `$.state`; the band
// above the prompt, the rewritten rows of bridge calls, the /clair pane and
// the status line all draw from it, with the words written in model.ts.

import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register, ToolCallResult } from 'claude-code'

import type { BridgeCall, ClairState, Step } from '../types'
import * as M from './model'

const STATE = atom({ plugin: 'mode-clair', key: 'state' } as const, M.EMPTY)
const SELECTED = atom({ plugin: 'mode-clair', key: 'selected' } as const, null)
const PANE = 'clair'
const POLL_MS = 3000

type Engine = EngineInterface

async function change($: Engine, fn: (s: ClairState) => ClairState): Promise<ClairState> {
  let after = M.EMPTY
  await update($, STATE, s => {
    after = fn(s ?? M.EMPTY)
    return after
  })
  $.ui.status(M.statusLine(after))
  return after
}

export const register: Register = on => {
  // --- Session: the /clair command and the workflow journal's reader -------

  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'clair',
      description: 'Mode clair : où on en est, ce qui t’attend, et le pipeline de chaque machine',
    })
    $.clock.every(POLL_MS, () => {
      void pollJournal($)
    })
    return next(e)
  }).catch(($, e, next) => next(e))

  on('command.run', { command: 'clair' }, async $ => {
    await $.ui.open({ id: PANE, title: 'Mode clair' })
    const state = (await read($, STATE)) ?? M.EMPTY
    return { text: M.statusLine(state) ?? 'Mode clair : rien ne tourne, rien à faire pour toi.' }
  }).catch(() => ({ text: 'Mode clair : le panneau n’a pas pu s’ouvrir.' }))

  // --- Superpowers ----------------------------------------------------------

  on('tool.call', { tool: 'Skill' }, async ($, e, next) => {
    await change($, s => ({ ...s, superpowers: M.onSkill(s.superpowers, e.skill) }))
    return next(e)
  }).catch(($, e, next) => next(e))

  on('tool.call', { tool: 'Write' }, async ($, e, next) => {
    const ran = await next(e)
    if (ran.deny === undefined && ran.isError !== true) {
      await change($, s => ({ ...s, superpowers: M.onWrite(s.superpowers, e.file_path, e.content) }))
    }
    return ran
  }).catch(($, e, next) => next(e))

  on('tool.call', { tool: 'Agent' }, async ($, e, next) => {
    await change($, s => ({ ...s, superpowers: M.onAgent(s.superpowers, e.description, e.prompt) }))
    return next(e)
  }).catch(($, e, next) => next(e))

  // --- ultracode workflows --------------------------------------------------

  on('tool.call', { tool: 'Workflow' }, async ($, e, next) => {
    const now = await $.clock.now()
    const ran = await next(e)
    if (ran.deny !== undefined || ran.isError === true) return ran
    const result = ran.result
    await change($, s => {
      const wf = M.newWorkflow(e.script, e.name ?? result.workflowName, now)
      return {
        ...s,
        workflow: {
          ...wf,
          runId: result.runId,
          taskId: result.taskId,
          journalPath: result.transcriptDir ? `${result.transcriptDir}/journal.jsonl` : undefined,
        },
      }
    })
    return ran
  }).catch(($, e, next) => next(e))

  on('agent.spawn', async ($, e, next) => {
    const spawned = await next(e)
    if (e.workflow && 'agentId' in spawned && spawned.agentId) {
      const id = spawned.agentId
      await change($, s => {
        const wf = s.workflow
        if (!wf || wf.isDone || (wf.runId && wf.runId !== e.workflow?.runId)) return s
        if (wf.agents.some(a => a.id === id)) return s
        return { ...s, workflow: { ...wf, agents: [...wf.agents, { id, label: e.description, isDone: false, isFailed: false }] } }
      })
    }
    return spawned
  }).catch(($, e, next) => next(e))

  on('turn.complete', async ($, e, next) => {
    const id = e.agentId
    if (id) {
      await change($, s => {
        const wf = s.workflow
        if (!wf || !wf.agents.some(a => a.id === id)) return s
        const agents = wf.agents.map(a => (a.id === id ? { ...a, isDone: true, isFailed: a.isFailed || e.isAborted } : a))
        return { ...s, workflow: { ...wf, agents } }
      })
    }
    return next(e)
  }).catch(($, e, next) => next(e))

  on('session.append', async ($, e, next) => {
    const stored = await next(e)
    const content = e.message.content
    const text = typeof content === 'string'
      ? content
      : Array.isArray(content)
        ? content.map(b => (b && typeof b === 'object' && 'text' in b && typeof b.text === 'string' ? b.text : '')).join('\n')
        : ''
    if (text.includes('<task-notification>')) {
      const state = (await read($, STATE)) ?? M.EMPTY
      if (state.workflow && !state.workflow.isDone && M.isWorkflowDoneNotice(text, state.workflow.taskId)) {
        await pollJournal($)
        await change($, s => (s.workflow ? { ...s, workflow: { ...s.workflow, isDone: true } } : s))
      }
    }
    return stored
  }).catch(($, e, next) => next(e))

  // --- bridge-mcp: through MCP and through `bridge-mcp tool` in Bash --------

  on('tool.call', async ($, e, next) => {
    if (!M.isBridgeMcpTool(e.tool)) return next(e)
    const start = M.parseMcpCall(e.tool, e as Record<string, unknown>)
    return trackCall($, e.tool_use_id, start, e.agentId, () => next(e))
  }).catch(($, e, next) => next(e))

  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    const start = M.parseCliCall(e.command)
    if (!start) return next(e)
    return trackCall($, e.tool_use_id, start, e.agentId, () => next(e))
  }).catch(($, e, next) => next(e))

  // A confirmation form from the bridge: the call waiting is the newest one
  // still running through MCP (the form names no call; one at a time is the
  // common case, and the pane says which machine it believes it is).
  on('classic.Elicitation', async ($, e, next) => {
    if (/bridge/i.test(e.mcp_server_name)) {
      await change($, s => {
        const running = [...s.calls].reverse().find(c => c.via === 'mcp' && c.state === 'running')
        return running ? M.patchCall(s, running.id, { state: 'you' }) : s
      })
    }
    return next(e)
  }).catch(($, e, next) => next(e))

  on('classic.ElicitationResult', async ($, e, next) => {
    if (/bridge/i.test(e.mcp_server_name)) {
      await change($, s => {
        const waiting = [...s.calls].reverse().find(c => c.state === 'you')
        if (!waiting) return s
        return e.action === 'accept'
          ? M.patchCall(s, waiting.id, { state: 'running', confirmed: true })
          : M.patchCall(s, waiting.id, { state: 'running' })
      })
    }
    return next(e)
  }).catch(($, e, next) => next(e))

  // --- Drawing ---------------------------------------------------------------

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    if (e.props.hasSurvey) return next(e)
    const state = (await read($, STATE)) ?? M.EMPTY
    const band = bandContent(state, await $.clock.now())
    if (!band) return next(e)
    const { Box, Text } = $.ui.resolve(e)
    return (
      <Box flexDirection="column" width={e.props.bodyColumns}>
        <Text wrap="truncate-end">
          <Text bold>{band.title}</Text>
          {'   '}
          {stepsInline(Text, band.steps)}
        </Text>
        <Box flexDirection="row" justifyContent="space-between" gap={2}>
          <Text wrap="truncate-end">{band.detail}</Text>
          {band.forYou.isAlert ? (
            <Text bold color="warning">{band.forYou.text}</Text>
          ) : (
            <Text>
              pour toi : <Text color="success">{band.forYou.text}</Text>
            </Text>
          )}
        </Box>
        {band.also ? (
          <Text dimColor wrap="truncate-end">
            {band.also}
          </Text>
        ) : null}
      </Box>
    )
  }).catch(($, e, next) => next(e))

  on('ui.render', { component: 'ToolResult' }, async ($, e, next) => {
    const state = (await read($, STATE)) ?? M.EMPTY
    const call = state.calls.find(c => c.id === e.props.tool_use_id)
    if (!call) return next(e)
    const { Box, Text } = $.ui.resolve(e)
    const now = await $.clock.now()
    const trust = M.trustSentence(call)
    const own = await next(e)
    return (
      <Box flexDirection="column">
        <Text>
          {callMark(Text, call)} {hostDots(Text, call.hosts)}
          <Text bold>{M.callHeadline(call, now)}</Text>
        </Text>
        <Text wrap="truncate-end">{stepsInline(Text, M.bridgeSteps(call, now))}</Text>
        {trust ? <Text bold>{trust}</Text> : null}
        {own}
      </Box>
    )
  }).catch(($, e, next) => next(e))

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const state = (await read($, STATE)) ?? M.EMPTY
    const selected = await read($, SELECTED)
    const now = await $.clock.now()
    const { Box, Text, Button } = $.ui.resolve(e)
    const hosts = M.machines(state)
    const chosen = hosts.find(m => m.host === selected) ?? hosts.find(m => m.last.state === 'you') ?? hosts.at(-1)
    const sp = state.superpowers
    const wf = state.workflow
    const trouble = M.problems(state).slice(-5)
    return (
      <Box flexDirection="column" gap={1} width={e.props.bodyColumns}>
        {wf ? (
          <Box flexDirection="column">
            <Text dimColor>WORKFLOW « {wf.name} »</Text>
            {wf.goal ? <Text dimColor>But, selon Claude : « {wf.goal} »</Text> : null}
            {stepsColumn(Box, Text, M.workflowSteps(wf))}
            {M.phaseLine(wf) ? <Text>{M.phaseLine(wf)}</Text> : null}
          </Box>
        ) : null}
        {sp ? (
          <Box flexDirection="column">
            <Text dimColor>PLAN{sp.planTitle ? ` « ${sp.planTitle} »` : ''}</Text>
            {stepsColumn(Box, Text, M.spSteps(sp))}
            {sp.tasks.length ? stepsColumn(Box, Text, taskList(sp.tasks, sp.currentTask)) : null}
            <Text>
              <Text dimColor>Pourquoi cette étape : </Text>
              {M.spWhy(sp)}
            </Text>
          </Box>
        ) : null}
        <Box flexDirection="column">
          <Text dimColor>MACHINES</Text>
          {hosts.length === 0 ? <Text dimColor>aucun appel au bridge pour l’instant.</Text> : null}
          {hosts.map(m => (
            <Button key={`m-${m.host}`} plain onPress={() => update($, SELECTED, () => m.host)}>
              <Text color={M.machineColor(m.host)}>●</Text> {m.host}{' '}
              <Text color={stateColor(m.last.state)}>{M.STATE_WORD[m.last.state]}</Text>
              <Text dimColor>{` · ${m.count} appel${m.count > 1 ? 's' : ''}${m.changed ? ` · ✎ ${m.changed}` : ''}`}</Text>
            </Button>
          ))}
        </Box>
        {chosen ? (
          <Box flexDirection="column">
            <Text>
              <Text color={M.machineColor(chosen.host)}>●</Text> <Text bold>{chosen.host}</Text>
              <Text dimColor>{` · dernier appel : ${chosen.last.tool}`}</Text>
            </Text>
            {chosen.last.command ? <Text bold>$ {chosen.last.command}</Text> : null}
            {stepsColumn(Box, Text, M.bridgeSteps(chosen.last, now))}
            {M.trustSentence(chosen.last) ? <Text bold>{M.trustSentence(chosen.last)}</Text> : null}
          </Box>
        ) : null}
        {trouble.length ? (
          <Box flexDirection="column">
            <Text dimColor>À REGARDER</Text>
            {trouble.map(c => (
              <Text key={`p-${c.id}`}>
                <Text color="error">✗</Text> {M.callHeadline(c, now)}
              </Text>
            ))}
          </Box>
        ) : null}
        <Text dimColor>Tab : choisir une machine · Entrée : voir son pipeline · Échap : fermer</Text>
      </Box>
    )
  }).catch(($, e) => {
    const { Text } = $.ui.resolve(e)
    return <Text>Mode clair : le panneau n’a pas pu se dessiner. Les rangées et la bande restent à jour.</Text>
  })
}

// ---------------------------------------------------------------------------

async function trackCall(
  $: Engine,
  id: string,
  start: M.CallStart,
  agentId: string | undefined,
  run: () => Promise<ToolCallResult>,
): Promise<ToolCallResult> {
  const startedAt = await $.clock.now()
  const call: BridgeCall = { id, ...start, startedAt, state: 'running', confirmed: false, agentId }
  await change($, s => M.addCall(s, call))
  const ran = await run()
  const endedAt = await $.clock.now()
  if (ran.deny !== undefined) {
    await change($, s => M.patchCall(s, id, { endedAt, state: 'declined', reason: 'refusé dans Claude Code' }))
    return ran
  }
  const outcome = M.classify({
    isError: ran.isError === true,
    text: typeof ran.text === 'string' ? ran.text : bashText(ran.result),
    readOnly: ran.isReadOnly === true ? true : undefined,
    tool: start.tool,
    via: start.via,
  })
  await change($, s => M.patchCall(s, id, { endedAt, ...outcome }))
  return ran
}

function bashText(result: unknown): string {
  if (!result || typeof result !== 'object') return ''
  const r = result as { stdout?: unknown; stderr?: unknown }
  return [r.stdout, r.stderr].filter((x): x is string => typeof x === 'string').join('\n')
}

async function pollJournal($: Engine): Promise<void> {
  const state = (await read($, STATE)) ?? M.EMPTY
  const wf = state.workflow
  if (!wf || wf.isDone || !wf.journalPath) return
  let journal: string
  try {
    journal = await $.fs.read(wf.journalPath)
  } catch {
    return
  }
  const folded = M.foldJournal(wf, journal)
  if (JSON.stringify(folded) === JSON.stringify(wf)) return
  await change($, s => (s.workflow && s.workflow.journalPath === wf.journalPath ? { ...s, workflow: M.foldJournal(s.workflow, journal) } : s))
}

// ---------------------------------------------------------------------------
// What the band says

type Band = {
  title: string
  steps: Step[]
  detail: string
  forYou: { text: string; isAlert: boolean }
  also?: string
}

function bandContent(state: ClairState, now: number): Band | undefined {
  const waiting = M.waitingCalls(state)
  const forYou = waiting.length
    ? { text: `⚠ à toi : réponds au formulaire (${M.hostsLabel(waiting[0]?.hosts ?? [])})`, isAlert: true }
    : { text: 'rien à faire', isAlert: false }
  const wf = state.workflow && !state.workflow.isDone ? state.workflow : undefined
  const sp = state.superpowers && state.superpowers.stage !== 'finish' ? state.superpowers : undefined
  const planLabel = (s: typeof sp) => (s?.planTitle ? `plan « ${s.planTitle} »` : 'Superpowers')

  if (wf) {
    return {
      title: `workflow « ${wf.name} »`,
      steps: M.workflowSteps(wf),
      detail: M.phaseLine(wf) ?? 'les agents démarrent',
      forYou,
      also: sp ? `aussi en cours : ${planLabel(sp)}${sp.currentTask ? `, tâche ${sp.currentTask} sur ${sp.tasks.length || '?'}` : ''}` : undefined,
    }
  }
  if (sp) {
    const task = M.taskTitle(sp)
    return {
      title: planLabel(sp),
      steps: M.spSteps(sp),
      detail: sp.stage === 'tasks' && task ? `${task} : ${stepsText(M.taskSteps(sp))}` : `pourquoi : ${M.spWhy(sp)}`,
      forYou,
    }
  }
  const last = state.calls.at(-1)
  if (!last) return undefined
  if (last.state === 'running' || last.state === 'you') {
    return {
      title: `bridge · ${M.hostsLabel(last.hosts)}`,
      steps: M.bridgeSteps(last, now),
      detail: `${last.tool}${last.command ? ` · ${M.clip(last.command, 60)}` : ''}`,
      forYou,
    }
  }
  return {
    title: 'clair',
    steps: [],
    detail: 'rien ne tourne · détails : /clair',
    forYou,
  }
}

// ---------------------------------------------------------------------------
// Drawing helpers: steps as one line, steps as a column

type TextTag = (props: Record<string, unknown>, ...children: unknown[]) => unknown

function mark(step: Step): { glyph: string; color: string } {
  if (step.color && step.status === 'done') return { glyph: '●', color: step.color }
  switch (step.status) {
    case 'done':
      return { glyph: '✓', color: 'success' }
    case 'current':
      return { glyph: '●', color: 'claude' }
    case 'you':
      return { glyph: '⚠', color: 'warning' }
    case 'problem':
      return { glyph: '✗', color: 'error' }
    default:
      return { glyph: '○', color: 'inactive' }
  }
}

function labelColor(step: Step): string | undefined {
  if (step.status === 'next' || step.status === 'skipped') return 'inactive'
  if (step.status === 'you') return 'warning'
  if (step.status === 'problem') return 'error'
  return undefined
}

function stepText(step: Step): string {
  return `${step.label}${step.detail ? ` ${step.detail}` : ''}`
}

function stepsText(steps: Step[]): string {
  return steps.map(s => `${mark(s).glyph} ${stepText(s)}`).join(' → ')
}

function stepsInline(Text: any, steps: Step[]) {
  return steps.map((step, i) => {
    const m = mark(step)
    return (
      <Text key={`s${i}`}>
        {i > 0 ? <Text color="subtle"> ── </Text> : null}
        <Text color={m.color} bold={step.status === 'current' || step.status === 'you'}>
          {m.glyph}
        </Text>
        <Text color={labelColor(step)} bold={step.status === 'current'}>{` ${stepText(step)}`}</Text>
      </Text>
    )
  })
}

function stepsColumn(Box: any, Text: any, steps: Step[]) {
  return (
    <Box flexDirection="column">
      {steps.map((step, i) => {
        const m = mark(step)
        return (
          <Text key={`c${i}`}>
            <Text color={m.color} bold>
              {m.glyph}
            </Text>
            <Text color={labelColor(step)} bold={step.status === 'current'}>{`  ${step.label}`}</Text>
            {step.detail ? <Text dimColor>{`  ${step.detail}`}</Text> : null}
          </Text>
        )
      })}
    </Box>
  )
}

function taskList(tasks: string[], current: number | undefined): Step[] {
  return tasks.map((title, i) => {
    const n = i + 1
    const status = current === undefined ? 'next' : n < current ? 'done' : n === current ? 'current' : 'next'
    return { label: `${n}  ${title}`, status }
  })
}

function callMark(Text: any, call: BridgeCall) {
  const glyph = M.callGlyph(call.state)
  const color =
    call.state === 'you'
      ? 'warning'
      : call.state === 'read'
        ? 'success'
        : call.state === 'changed' || call.state === 'running'
          ? 'text'
          : 'error'
  return (
    <Text color={color} bold>
      {glyph}
    </Text>
  )
}

function hostDots(Text: any, hosts: string[]) {
  // `h` is JSX's factory here: no parameter may take that name.
  return hosts.slice(0, 3).map(host => (
    <Text key={`d-${host}`} color={M.machineColor(host)}>
      {'● '}
    </Text>
  ))
}

function stateColor(state: BridgeCall['state']): string {
  if (state === 'you') return 'warning'
  if (state === 'read') return 'success'
  if (state === 'changed' || state === 'running') return 'text'
  return 'error'
}
