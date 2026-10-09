// The state contract of the mode-clair plugin: what it keeps in `$.state`.
//
// Everything here is plain data, so a hot reload keeps it and a test can
// build it by hand. Field names are English; every word the person reads is
// French and lives in hooks/model.ts.

/** Where one step of a pipeline stands. */
export type StepStatus = 'done' | 'current' | 'next' | 'skipped' | 'you' | 'problem'

/** One step of a pipeline, already worded for the person. */
export type Step = {
  label: string
  status: StepStatus
  /** A short note after the label (`0,4 s`, `refusé par toi`). */
  detail?: string
  /** A raw color for the step's mark: the machine's, on the machine step. */
  color?: string
}

/** What became of one call to the bridge, as seen from outside it. */
export type CallState =
  | 'running'
  | 'you'
  | 'read'
  | 'changed'
  | 'truncated'
  | 'denied'
  | 'unknown-host'
  | 'rate-limited'
  | 'declined'
  | 'unreachable'
  | 'failed'

/** One call to bridge-mcp, through MCP or through `bridge-mcp tool` in Bash. */
export type BridgeCall = {
  id: string
  /** The bridge tool's own name (`ssh_k8s_get`). */
  tool: string
  via: 'mcp' | 'cli'
  /** The machine(s) named by the call; empty when it named none. */
  hosts: string[]
  /** `command` for ssh_exec and its kin, when the call carried one. */
  command?: string
  sudo: boolean
  startedAt: number
  endedAt?: number
  state: CallState
  /** True once the person answered a confirmation form with accept. */
  confirmed: boolean
  /** The tool held the call read-only (MCP annotations), when the engine said. */
  readOnly?: boolean
  /** The bridge's own words for a refusal or a failure (`/dev/sda`, `code 1`). */
  reason?: string
  /** The first useful line of what came back. */
  summary?: string
  /** The subagent that made the call, when one did. */
  agentId?: string
}

/** The stages a Superpowers session walks through, in order. */
export type SpStage = 'framing' | 'spec' | 'plan' | 'tasks' | 'review' | 'finish'

/** Inside a task: who works on it right now. */
export type TaskRole = 'code' | 'review' | 'fix'

export type Superpowers = {
  stage: SpStage
  /** The skill seen last (`subagent-driven-development`). */
  skill?: string
  planTitle?: string
  planPath?: string
  /** Task titles, in plan order (index 0 is task 1). */
  tasks: string[]
  /** 1-based number of the task in progress. */
  currentTask?: number
  role?: TaskRole
  /** Tasks a reviewer already looked at once (so a new coder is a fix). */
  reviewed: number[]
}

export type WorkflowAgent = {
  id: string
  label?: string
  phase?: string
  isDone: boolean
  isFailed: boolean
}

export type Workflow = {
  name: string
  /** The script's own `meta.description`, quoted as Claude wrote it. */
  goal?: string
  phases: string[]
  runId?: string
  taskId?: string
  journalPath?: string
  agents: WorkflowAgent[]
  /** Phase titles the journal says started, in the order they started. */
  startedPhases: string[]
  isDone: boolean
  startedAt: number
}

export type ClairState = {
  superpowers?: Superpowers
  workflow?: Workflow
  calls: BridgeCall[]
}

declare module 'claude-code' {
  interface PluginState {
    'mode-clair': {
      state: ClairState
      /** The machine whose last call the pane shows. */
      selected: string | null
    }
  }
}
