import { describe, expect, test } from 'claude-code/testing'

import type { BridgeCall, ClairState, Workflow } from '../types'
import * as M from '../hooks/model'

const call = (patch: Partial<BridgeCall>): BridgeCall => ({
  id: 't1',
  tool: 'ssh_disk_usage',
  via: 'mcp',
  hosts: ['pi-k3s'],
  sudo: false,
  startedAt: 0,
  endedAt: 400,
  state: 'read',
  confirmed: false,
  ...patch,
})

describe('recognising a call to the bridge', () => {
  test('MCP tool names of the bridge, plugin-bundled or not', () => {
    expect(M.isBridgeMcpTool('mcp__bridge-mcp__ssh_exec')).toBe(true)
    expect(M.isBridgeMcpTool('mcp__plugin_bridge-mcp_bridge__ssh_k8s_get')).toBe(true)
    expect(M.isBridgeMcpTool('mcp__github__get_me')).toBe(false)
    expect(M.bridgeToolName('mcp__plugin_bridge-mcp_bridge__ssh_k8s_get')).toBe('ssh_k8s_get')
  })

  test('a CLI call, quotes and all', () => {
    const c = M.parseCliCall(`bridge-mcp tool ssh_exec host=web-02 command="rm -rf '/var/log/old'" sudo=true --json`)
    expect(c).toEqual({ tool: 'ssh_exec', via: 'cli', hosts: ['web-02'], command: "rm -rf '/var/log/old'", sudo: true })
    expect(M.parseCliCall('cargo test')).toBeUndefined()
    expect(M.parseCliCall('bridge-mcp list-tools')).toBeUndefined()
  })

  test('an MCP call with several machines', () => {
    const c = M.parseMcpCall('mcp__bridge-mcp__ssh_exec_multi', { hosts: ['web-01', 'web-02'], command: 'uptime' })
    expect(c.hosts).toEqual(['web-01', 'web-02'])
    expect(M.hostsLabel(['a', 'b', 'c', 'd'])).toBe('a +3')
  })
})

describe('what the bridge answered', () => {
  const base = { isError: true, tool: 'ssh_exec', via: 'mcp' as const }

  test('each refusal and failure has its own word', () => {
    expect(M.classify({ ...base, text: 'Command denied: matches blacklist pattern >\\s*/dev/sd' }).state).toBe('denied')
    expect(M.classify({ ...base, text: "Rate limit exceeded for host 'web-02'. Please wait" }).state).toBe('rate-limited')
    expect(M.classify({ ...base, text: 'Unknown host: web-99' }).reason).toBe("web-99 n'est pas dans ta config")
    expect(M.classify({ ...base, text: 'SSH connection failed to db-02: Connection refused' })).toEqual({
      state: 'unreachable',
      reason: 'connexion refusée',
    })
    expect(M.classify({ ...base, text: 'User declined execution of destructive tool `ssh_exec`.' }).state).toBe('declined')
    expect(M.classify({ ...base, text: '[exit:1]\nJob for php-fpm.service failed' })).toEqual({
      state: 'failed',
      reason: 'code 1',
      summary: 'Job for php-fpm.service failed',
    })
  })

  test('a read through MCP needs the engine to say read-only', () => {
    const ok = { isError: false, text: 'Filesystem Size Used', tool: 'ssh_disk_usage', via: 'mcp' as const }
    expect(M.classify({ ...ok, readOnly: true }).state).toBe('read')
    expect(M.classify(ok).state).toBe('changed')
  })

  test('through the CLI the name decides, and a free command is never a read', () => {
    const ok = { isError: false, text: 'ok', via: 'cli' as const }
    expect(M.classify({ ...ok, tool: 'ssh_k8s_get' }).state).toBe('read')
    expect(M.classify({ ...ok, tool: 'ssh_service_restart' }).state).toBe('changed')
    expect(M.classify({ ...ok, tool: 'ssh_exec' }).state).toBe('changed')
  })

  test('a truncated answer says so', () => {
    expect(M.classify({ isError: false, text: 'lines…\noutput_id: out-002a', tool: 'ssh_journal_query', via: 'mcp', readOnly: true }).state).toBe('truncated')
  })
})

describe('the pipeline of one call', () => {
  const labels = (c: BridgeCall) => M.bridgeSteps(c, 1000).map(s => `${s.label}:${s.status}`)

  test('a read: everything passed, no accord needed', () => {
    expect(labels(call({ readOnly: true }))).toEqual([
      'permission:done',
      'accord:skipped',
      'validation:done',
      'liste noire:done',
      'pi-k3s:done',
      'réponse:done',
    ])
  })

  test('denied by the blacklist: nothing reached the machine', () => {
    const c = call({ state: 'denied', tool: 'ssh_exec', hosts: ['web-02'] })
    expect(labels(c)).toContain('liste noire:problem')
    expect(labels(c)).toContain('web-02:next')
    expect(M.trustSentence(c)).toBe("Rien n'est parti vers web-02.")
  })

  test('waiting on the person: the accord is theirs, the rest has not happened', () => {
    const c = call({ state: 'you', sudo: true })
    expect(labels(c)).toEqual([
      'permission:done',
      'ton accord:you',
      'validation:next',
      'sudo:next',
      'liste noire:next',
      'pi-k3s:next',
      'réponse:done',
    ])
  })

  test('a command that ran and failed may have changed something', () => {
    expect(M.trustSentence(call({ state: 'failed', reason: 'code 1' }))).toMatch(/a pu changer/)
  })

  test('the same machine always gets the same color', () => {
    expect(M.machineColor('web-02')).toBe(M.machineColor('web-02'))
    expect(M.MACHINE_PALETTE).toContain(M.machineColor('pi-k3s'))
  })
})

describe('Superpowers', () => {
  const plan = [
    '# Ajouter l’export CSV Implementation Plan',
    '',
    '### Task 1: Ajouter la commande export',
    '### Task 2: Lire les résultats',
    '### Task 3: Écrire le fichier CSV',
  ].join('\n')

  test('a plan file gives its title and tasks', () => {
    expect(M.parsePlan(plan)).toEqual({
      title: 'Ajouter l’export CSV',
      tasks: ['Ajouter la commande export', 'Lire les résultats', 'Écrire le fichier CSV'],
    })
  })

  test('a session walks framing → plan → tasks, and a re-coded task is a fix', () => {
    let sp = M.onSkill(undefined, 'superpowers:brainstorming')
    expect(sp?.stage).toBe('framing')
    sp = M.onWrite(sp, '/repo/docs/superpowers/specs/2026-10-09-csv.md', '# spec')
    expect(sp?.stage).toBe('spec')
    sp = M.onWrite(sp, '/repo/docs/superpowers/plans/2026-10-09-csv.md', plan)
    expect(sp?.stage).toBe('plan')
    sp = M.onSkill(sp, 'superpowers:subagent-driven-development')
    sp = M.onAgent(sp, 'Implement Task 3', 'You are implementing Task 3: Écrire le fichier CSV')
    expect(sp?.currentTask).toBe(3)
    expect(sp?.role).toBe('code')
    sp = M.onAgent(sp, 'Review Task 3', 'Review the implementation of Task 3')
    expect(sp?.role).toBe('review')
    sp = M.onAgent(sp, 'Implement Task 3', 'Fix the issues found in Task 3')
    expect(sp?.role).toBe('fix')
    expect(M.spSteps(sp!).map(s => s.status)).toEqual(['done', 'done', 'done', 'current', 'next', 'next'])
    expect(M.spSteps(sp!)[3]?.label).toBe('tâches 3 sur 3')
    expect(M.taskTitle(sp!)).toBe('tâche 3 « Écrire le fichier CSV »')
  })

  test('a skill of another plugin changes nothing', () => {
    expect(M.onSkill(undefined, 'artifact-design')).toBeUndefined()
  })
})

describe('ultracode workflows', () => {
  const script = `export const meta = {
    name: 'audit-disques',
    description: 'trouver ce qui remplit les disques',
    phases: [{ title: 'mesure', detail: 'df' }, { title: 'analyse' }, { title: "ménage" }],
  }
  phase('mesure')`

  test('the meta block gives name, goal and phases', () => {
    expect(M.parseWorkflowMeta(script)).toEqual({
      name: 'audit-disques',
      goal: 'trouver ce qui remplit les disques',
      phases: ['mesure', 'analyse', 'ménage'],
    })
  })

  test('the journal moves the phases along, and a broken line is skipped', () => {
    const wf: Workflow = M.newWorkflow(script, undefined, 0)
    const journal = [
      '{"type":"launched"}',
      '{"type":"started","agentId":"a1","label":"mesure web-01","phase":"mesure"}',
      '{"type":"result","agentId":"a1","result":{"ok":true}}',
      'not json',
      '{"type":"started","agentId":"a2","label":"analyse web-01","phase":"analyse"}',
      '{"type":"started","agentId":"a3","label":"analyse db-01","phase":"analyse"}',
      '{"type":"result","agentId":"a3","result":null}',
    ].join('\n')
    const folded = M.foldJournal(wf, journal)
    expect(M.currentPhase(folded)).toBe('analyse')
    expect(M.workflowSteps(folded).map(s => `${s.label}:${s.status}`)).toEqual([
      'mesure:done',
      'analyse:problem',
      'ménage:next',
      'fin:next',
    ])
    expect(M.phaseLine(folded)).toBe('« analyse » : 1 agent en cours · 1 sans résultat')
  })

  test('the task notification that ends the run', () => {
    const text = '<task-notification><task-id>w0rn</task-id><status>completed</status></task-notification>'
    expect(M.isWorkflowDoneNotice(text, 'w0rn')).toBe(true)
    expect(M.isWorkflowDoneNotice(text, 'other')).toBe(false)
  })
})

describe('the status line', () => {
  test('a waiting confirmation comes first', () => {
    const state: ClairState = { calls: [call({ state: 'read' }), call({ id: 't2', state: 'you', hosts: ['web-02'] })] }
    expect(M.statusLine(state)).toBe('clair · ⚠ web-02 attend ton accord')
  })

  test('nothing happened: nothing to say', () => {
    expect(M.statusLine(M.EMPTY)).toBeUndefined()
  })

  test('calls only: machines, changes, problems', () => {
    const state: ClairState = {
      calls: [call({}), call({ id: 't2', state: 'changed', hosts: ['web-02'] }), call({ id: 't3', state: 'denied', hosts: ['web-02'] })],
    }
    expect(M.statusLine(state)).toBe('clair · 2 machines · ✎ 1 · ✗ 1')
  })
})
