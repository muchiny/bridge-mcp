import { describe, expect, mock, test } from 'claude-code/testing'
import type { On } from 'claude-code'

const SURFACES = ['terminal', 'desktop'] as const
const PLUGIN = 'mode-clair'

/**
 * The world beneath the plugin: a clock in memory, a status line that keeps
 * nothing, and the engine's own drawing of a row as one plain Text, so a test
 * can tell the plugin's lines from what it leaves to the engine.
 */
function world(on: On) {
  mock.clock(on, { now: 1_000 })
  on('ui.status', () => ({ value: undefined }))
  on('ui.render', () => ({ type: 'Text', props: {}, children: ['(rendu du moteur)'] }) as never)
}

const BAND_PROPS = {
  hasSurvey: false,
  isWorking: true,
  maxRows: 12,
  bodyColumns: 120,
  scroll: { bodyRows: 12, offset: 0, total: 0 },
  view: {},
}

describe('a bridge call, drawn', () => {
  test('a read: the row names the machine and draws the pipeline', async ($, on) => {
    world(on)
    on('tool.call', () => ({ result: { content: [] }, text: 'Filesystem Size Used\n/dev/mmcblk0p2 58G 53G', isReadOnly: true }))
    await $.tool.call({ tool: 'mcp__bridge-mcp__ssh_disk_usage', tool_use_id: 'toolu_read', host: 'pi-k3s' })

    for (const surface of SURFACES) {
      const ui = await $.ui.mount({
        plugin: PLUGIN,
        surface,
        component: 'ToolResult',
        requestId: 'toolu_read',
        props: { tool_use_id: 'toolu_read', tool: 'mcp__bridge-mcp__ssh_disk_usage', output: {}, isErrored: false },
      })
      expect(await ui.find({ type: 'Text', text: /pi-k3s · lecture/ })).toBeDefined()
      expect(await ui.find({ type: 'Text', text: /liste noire/ })).toBeDefined()
      await ui.unmount()
    }
  })

  test('a refusal says nothing reached the machine', async ($, on) => {
    world(on)
    on('tool.call', () => ({ result: 'Command denied: blacklist', text: 'Command denied: blacklist', isError: true }))
    await $.tool.call({ tool: 'mcp__bridge-mcp__ssh_exec', tool_use_id: 'toolu_deny', host: 'web-02', command: 'rm -rf /var/log/old/*' })

    for (const surface of SURFACES) {
      const ui = await $.ui.mount({
        plugin: PLUGIN,
        surface,
        component: 'ToolResult',
        requestId: 'toolu_deny',
        props: { tool_use_id: 'toolu_deny', tool: 'mcp__bridge-mcp__ssh_exec', output: {}, isErrored: true },
      })
      expect(await ui.find({ type: 'Text', text: "Rien n'est parti vers web-02." })).toBeDefined()
      await ui.unmount()
    }
  })

  test('a row of another tool is left to the engine', async ($, on) => {
    world(on)
    const ui = await $.ui.mount({
      plugin: PLUGIN,
      surface: 'terminal',
      component: 'ToolResult',
      requestId: 'toolu_other',
      props: { tool_use_id: 'toolu_other', tool: 'Read', output: {}, isErrored: false },
    })
    expect(await ui.find({ type: 'Text', text: '(rendu du moteur)' })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /liste noire/ })).toBeUndefined()
    await ui.unmount()
  })
})

describe('the band above the prompt', () => {
  test('a Superpowers task shows the stages and the task loop', async ($, on) => {
    world(on)
    on('tool.call', () => ({ result: { success: true, commandName: 'x' }, text: 'ok' }))
    await $.tool.call({ tool: 'Skill', tool_use_id: 'toolu_s1', skill: 'superpowers:subagent-driven-development' })
    await $.tool.call({
      tool: 'Agent',
      tool_use_id: 'toolu_a1',
      description: 'Implement Task 3',
      prompt: 'You are implementing Task 3: Écrire le fichier CSV',
    })

    for (const surface of SURFACES) {
      const ui = await $.ui.mount({ plugin: PLUGIN, surface, component: 'AbovePrompt', props: BAND_PROPS })
      expect(await ui.find({ type: 'Text', text: /tâche 3/ })).toBeDefined()
      expect(await ui.find({ type: 'Text', text: /coder/ })).toBeDefined()
      expect(await ui.find({ type: 'Text', text: /rien à faire/ })).toBeDefined()
      await ui.unmount()
    }
  })

  test('nothing happened: the band is the engine\'s own', async ($, on) => {
    world(on)
    const ui = await $.ui.mount({ plugin: PLUGIN, surface: 'terminal', component: 'AbovePrompt', props: BAND_PROPS })
    expect(await ui.find({ type: 'Text', text: '(rendu du moteur)' })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /rien à faire/ })).toBeUndefined()
    await ui.unmount()
  })
})

describe('the /clair pane', () => {
  test('lists the machines and shows the pipeline of the one pressed', async ($, on) => {
    world(on)
    on('tool.call', ($, e) =>
      e.tool.endsWith('ssh_exec')
        ? { result: 'Command denied: blacklist', text: 'Command denied: blacklist', isError: true }
        : { result: { content: [] }, text: 'ok', isReadOnly: true },
    )
    await $.tool.call({ tool: 'mcp__bridge-mcp__ssh_disk_usage', tool_use_id: 'toolu_p1', host: 'pi-k3s' })
    await $.tool.call({ tool: 'mcp__bridge-mcp__ssh_exec', tool_use_id: 'toolu_p2', host: 'web-02', command: 'rm -rf /var/log/old/*' })

    for (const surface of SURFACES) {
      const ui = await $.ui.mount({
        plugin: PLUGIN,
        surface,
        component: 'Pane',
        requestId: 'clair',
        props: { title: 'Mode clair', isFocused: true, bodyColumns: 70, placement: 'dock', scroll: { bodyRows: 30, offset: 0, total: 0 }, view: {} } as never,
      })
      expect(await ui.find({ key: 'm-pi-k3s' })).toBeDefined()
      expect(await ui.find({ type: 'Text', text: /À REGARDER/ })).toBeDefined()
      await ui.press({ key: 'm-pi-k3s' })
      expect(await ui.find({ type: 'Text', text: /dernier appel : ssh_disk_usage/ })).toBeDefined()
      await ui.press({ key: 'm-web-02' })
      expect(await ui.find({ type: 'Text', text: '$ rm -rf /var/log/old/*' })).toBeDefined()
      expect(await ui.find({ type: 'Text', text: "Rien n'est parti vers web-02." })).toBeDefined()
      await ui.unmount()
    }
  })
})

describe('an ultracode workflow in the band', () => {
  test('the phases of the script become the pipeline', async ($, on) => {
    world(on)
    on('tool.call', () => ({ result: { status: 'async_launched', taskId: 'w1', runId: 'wf_1' }, text: 'launched' }))
    await $.tool.call({
      tool: 'Workflow',
      tool_use_id: 'toolu_w1',
      script: "export const meta = { name: 'audit-disques', description: 'faire de la place', phases: [{ title: 'mesure' }, { title: 'ménage' }] }",
    })
    const ui = await $.ui.mount({ plugin: PLUGIN, surface: 'terminal', component: 'AbovePrompt', props: BAND_PROPS })
    expect(await ui.find({ type: 'Text', text: /workflow « audit-disques »/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /mesure/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /ménage/ })).toBeDefined()
    await ui.unmount()
  })
})
