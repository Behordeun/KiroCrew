/**
 * Settings ▸ Chat ▸ Advanced, Context card: the idle compaction switch
 * (`session.idle_compaction`) and its minimum context field
 * (`session.idle_compaction_min_context_pct`).
 *
 * The claims: both rows show the stored value; the switch saves the new value
 * through the config API; the field is disabled while the switch is off; a typed
 * minimum saves on blur or Enter, and a value outside 40-90 shows the value the
 * server clamped it to (the write path clamps through the loader's own coercer
 * and returns a clamp notice) with a notice; a failed save keeps the typed value;
 * Settings search finds both rows and deep-links to their config keys.
 */

// SettingsSelect wraps Radix Select, whose portalled listbox jsdom cannot open.
vi.mock('@radix-ui/react-select', async () => await import('./__mocks__/@radix-ui/react-select'))

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Provider } from 'react-redux'
import { MemoryRouter, type NavigateFunction } from 'react-router-dom'
import { createTestStore } from './helpers'

const { kirocrewConfigMock, patchConfigMock } = vi.hoisted(() => ({
  kirocrewConfigMock: vi.fn(),
  patchConfigMock: vi.fn(() => Promise.resolve({})),
}))

vi.mock('../api/client', () => ({
  api: {
    dashboardConfig: () => Promise.resolve({
      restore_sessions: false, restore_window_minutes: 30, merge_queued_messages: false,
      default_memory_mode: 'persistent', widget_density: 'more', verbosity: 'default',
      quick_send: false, session_grid: false, tail_fork_enabled: false, link_previews: false,
      mcp_app_panel: false, folder_suggestions_enabled: true,
    }),
    updateDashboardConfig: () => Promise.resolve({}),
    kirocrewConfig: kirocrewConfigMock,
    kirocrewAgents: () => Promise.resolve({ agents: [], default_agent: 'default' }),
    agentResolvedModel: () => Promise.resolve({ model: '', pinned: false }),
    patchConfig: patchConfigMock,
    models: () => Promise.resolve([{ model_name: 'auto', description: 'Default' }]),
    voiceConfig: () => Promise.resolve({ enabled: false, voice: 'Ruth', engine: 'neural', rate: '100%', autoSpeak: false, aws_profile: '', region: '' }),
    sttConfig: () => Promise.resolve({ enabled: false, provider: '', model: '', available: false, streaming: false, transcribe_region: '', transcribe_profile: '', language_code: 'en-US', models: {}, language_codes: [] }),
    updateVoiceConfig: () => Promise.resolve({}),
    updateSttConfig: () => Promise.resolve({}),
    tipsStatus: () => Promise.resolve({ enabled_config: true, opted_out: false }),
    tipsFeedback: () => Promise.resolve({ ok: true }),
    featureVideoStatus: () => Promise.resolve({
      enabled: true, download_enabled: false, release: 'r1', cached: 0, total: 0, downloading: null,
    }),
    featureVideoFetchAll: () => Promise.resolve({ ok: true }),
  },
}))

import { ChatPanel } from '../pages/settings/ChatPanel'
import { createSettingsProvider } from '../components/commandPalette/providers/settingsProvider'
import { SETTINGS_REGISTRY } from '../components/commandPalette/settingsRegistry.gen'

const SWITCH = 'Compact Idle Chats Before Cache Expiry'
const FIELD = 'Idle Compaction Minimum Context'
const MIN_PATH = 'session.idle_compaction_min_context_pct'

function seedSession(session: Record<string, unknown>) {
  kirocrewConfigMock.mockImplementation(() => Promise.resolve({
    session: { autocompact_pct: 70, ...session },
    agent: { model: 'auto', reasoning_effort: '', completion_keep: 'head', completion_keep_chars: 3000, soft_stop_budget_secs: 10 },
    dashboard: { user_role: '', user_role_other: '', user_technical_level: '', prevent_sleep: false },
    knowledge: { embed_rate_limit: 120 },
  }) as never)
}

let lastQc: QueryClient

function wrap() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  lastQc = qc
  return render(
    <MemoryRouter initialEntries={['/settings?tab=chat&sub=advanced']}>
      <Provider store={createTestStore()}>
        <QueryClientProvider client={qc}>
          <ChatPanel />
        </QueryClientProvider>
      </Provider>
    </MemoryRouter>,
  )
}

async function settledSwitch() {
  const sw = await screen.findByRole('switch', { name: SWITCH })
  await waitFor(() => expect(sw).not.toHaveAttribute('aria-disabled'))
  return sw
}

async function field() {
  return (await screen.findByRole('spinbutton', { name: FIELD })) as HTMLInputElement
}

/** The field once the config has loaded and the switch is on. */
async function enabledField(value: number) {
  const input = await field()
  await waitFor(() => expect(input).not.toBeDisabled())
  await waitFor(() => expect(input).toHaveValue(value))
  return input
}

beforeEach(() => {
  localStorage.clear()
  kirocrewConfigMock.mockReset()
  patchConfigMock.mockReset()
  patchConfigMock.mockImplementation(() => Promise.resolve({}) as never)
  seedSession({})
})

describe('ChatPanel — idle compaction switch', () => {
  it('is off by default and keeps the minimum field disabled', async () => {
    wrap()
    const sw = await settledSwitch()
    expect(sw).toHaveAttribute('aria-checked', 'false')
    const input = await field()
    await waitFor(() => expect(input).toHaveValue(50))
    expect(input).toBeDisabled()
  })

  it('shows a saved on value and enables the minimum field', async () => {
    seedSession({ idle_compaction: true, idle_compaction_min_context_pct: 65 })
    wrap()
    const sw = await settledSwitch()
    expect(sw).toHaveAttribute('aria-checked', 'true')
    await enabledField(65)
  })

  it('saves the new value through the config API and holds it while the save runs', async () => {
    let settle: (v: unknown) => void = () => {}
    patchConfigMock.mockImplementationOnce(() => new Promise(r => { settle = r }) as never)
    wrap()
    const sw = await settledSwitch()
    fireEvent.click(sw)
    await waitFor(() => expect(patchConfigMock).toHaveBeenCalledWith('session.idle_compaction', true))
    expect(sw).toHaveAttribute('aria-checked', 'true')
    seedSession({ idle_compaction: true })
    settle({})
    await enabledField(50)
    expect(sw).toHaveAttribute('aria-checked', 'true')
  })

  it('surfaces a failed save and shows the stored value again', async () => {
    patchConfigMock.mockImplementationOnce(() => Promise.reject(new Error('boom')))
    wrap()
    const sw = await settledSwitch()
    fireEvent.click(sw)
    expect(await screen.findByText(/Failed to save idle compaction$/)).toBeInTheDocument()
    await waitFor(() => expect(sw).toHaveAttribute('aria-checked', 'false'))
  })

  it('stays on after a save that worked when the refetch that follows fails', async () => {
    wrap()
    const sw = await settledSwitch()
    kirocrewConfigMock.mockImplementation(() => Promise.reject(new Error('refetch down')))
    fireEvent.click(sw)
    await waitFor(() => expect(patchConfigMock).toHaveBeenCalledWith('session.idle_compaction', true))
    // The save has settled and the refetch after it has failed, so the switch
    // reads only the cache.
    await waitFor(() => expect(lastQc.isMutating()).toBe(0))
    await waitFor(() => expect(lastQc.getQueryState(['kirocrewConfig'])?.status).toBe('error'))
    expect(sw).toHaveAttribute('aria-checked', 'true')
  })

  it('scrolls the save-error banner into view when a save fails', async () => {
    const scroll = vi.fn()
    const original = Element.prototype.scrollIntoView
    Element.prototype.scrollIntoView = scroll
    try {
      patchConfigMock.mockImplementationOnce(() => Promise.reject(new Error('boom')))
      wrap()
      fireEvent.click(await settledSwitch())
      await screen.findByText(/Failed to save idle compaction$/)
      await waitFor(() => expect(scroll).toHaveBeenCalled())
    } finally {
      Element.prototype.scrollIntoView = original
    }
  })

  it('says on the row that each idle compaction costs credits', async () => {
    wrap()
    await settledSwitch()
    expect(screen.getByText(/extra model call that costs credits/)).toBeInTheDocument()
  })
})

describe('ChatPanel — idle compaction minimum context', () => {
  beforeEach(() => seedSession({ idle_compaction: true, idle_compaction_min_context_pct: 50 }))

  it('saves an in-range value on blur and shows no notice', async () => {
    wrap()
    const input = await enabledField(50)
    fireEvent.change(input, { target: { value: '62.5' } })
    fireEvent.blur(input)
    await waitFor(() => expect(patchConfigMock).toHaveBeenCalledWith(MIN_PATH, 62.5))
    expect(screen.queryByText(/outside the allowed range/)).not.toBeInTheDocument()
  })

  it('saves on Enter', async () => {
    wrap()
    const input = await enabledField(50)
    fireEvent.change(input, { target: { value: '80' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    await waitFor(() => expect(patchConfigMock).toHaveBeenCalledWith(MIN_PATH, 80))
  })

  it.each([
    [20, 40],
    [95, 90],
  ])('shows the value the server clamped %d to, with a notice', async (typed, stored) => {
    patchConfigMock.mockImplementationOnce(() => Promise.resolve({
      clamp_notice: { path: MIN_PATH, requested: typed, stored, min: 40, max: 90 },
    }) as never)
    wrap()
    const input = await enabledField(50)
    fireEvent.change(input, { target: { value: String(typed) } })
    fireEvent.blur(input)
    await waitFor(() => expect(patchConfigMock).toHaveBeenCalledWith(MIN_PATH, typed))
    expect(await screen.findByRole('status')).toHaveTextContent(/outside the allowed range/)
    expect(input).toHaveValue(stored)
  })

  it('sends nothing for an empty field and shows the stored value again', async () => {
    wrap()
    const input = await enabledField(50)
    fireEvent.change(input, { target: { value: '' } })
    fireEvent.blur(input)
    await waitFor(() => expect(input).toHaveValue(50))
    expect(patchConfigMock).not.toHaveBeenCalledWith(MIN_PATH, expect.anything())
  })

  it.each([
    { typed: 62.5, reply: {}, stored: 62.5 },
    { typed: 20, reply: { clamp_notice: { requested: 20, stored: 40, min: 40, max: 90 } }, stored: 40 },
  ])('keeps the stored minimum $stored in the config cache when the refetch after a save of $typed fails', async ({ typed, reply, stored }) => {
    seedSession({ idle_compaction: true })
    patchConfigMock.mockImplementationOnce(() => Promise.resolve(reply) as never)
    wrap()
    const input = await enabledField(50)
    kirocrewConfigMock.mockImplementation(() => Promise.reject(new Error('refetch down')))
    fireEvent.change(input, { target: { value: String(typed) } })
    fireEvent.blur(input)
    await waitFor(() => expect(patchConfigMock).toHaveBeenCalledWith(MIN_PATH, typed))
    await waitFor(() => expect(lastQc.isMutating()).toBe(0))
    await waitFor(() => expect(lastQc.getQueryState(['kirocrewConfig'])?.status).toBe('error'))
    const cached = lastQc.getQueryData<{ session?: Record<string, unknown> }>(['kirocrewConfig'])
    expect(cached?.session?.idle_compaction_min_context_pct).toBe(stored)
  })

  it('does not write the cache when a minimum save settles after the panel unmounts', async () => {
    seedSession({ idle_compaction: true })
    let settle: (v: unknown) => void = () => {}
    patchConfigMock.mockImplementationOnce(() => new Promise(r => { settle = r }) as never)
    const view = wrap()
    const input = await enabledField(50)
    fireEvent.change(input, { target: { value: '62.5' } })
    fireEvent.blur(input)
    await waitFor(() => expect(patchConfigMock).toHaveBeenCalledWith(MIN_PATH, 62.5))
    view.unmount()
    // A remounted panel saved 70 in the meantime.
    const cached = lastQc.getQueryData<{ session?: Record<string, unknown> }>(['kirocrewConfig'])
    lastQc.setQueryData(['kirocrewConfig'], { ...cached, session: { ...cached?.session, idle_compaction_min_context_pct: 70 } })
    settle({})
    await waitFor(() => expect(lastQc.isMutating()).toBe(0))
    const after = lastQc.getQueryData<{ session?: Record<string, unknown> }>(['kirocrewConfig'])
    expect(after?.session?.idle_compaction_min_context_pct).toBe(70)
  })

  it('scrolls the save-error banner into view when a save of the minimum fails', async () => {
    const scroll = vi.fn()
    const original = Element.prototype.scrollIntoView
    Element.prototype.scrollIntoView = scroll
    try {
      seedSession({ idle_compaction: true })
      patchConfigMock.mockImplementationOnce(() => Promise.reject(new Error('boom')))
      wrap()
      const input = await enabledField(50)
      fireEvent.change(input, { target: { value: '70' } })
      fireEvent.blur(input)
      await screen.findByText(/Failed to save idle compaction minimum context$/)
      await waitFor(() => expect(scroll).toHaveBeenCalled())
    } finally {
      Element.prototype.scrollIntoView = original
    }
  })

  it('keeps the typed value after a failed save and retries it on the next blur', async () => {
    patchConfigMock.mockImplementationOnce(() => Promise.reject(new Error('boom')))
    wrap()
    const input = await enabledField(50)
    fireEvent.change(input, { target: { value: '70' } })
    fireEvent.blur(input)
    expect(await screen.findByText(/Failed to save idle compaction minimum context/)).toBeInTheDocument()
    await waitFor(() => expect(input).not.toBeDisabled())
    expect(input).toHaveValue(70)
    patchConfigMock.mockClear()
    fireEvent.focus(input)
    fireEvent.blur(input)
    await waitFor(() => expect(patchConfigMock).toHaveBeenCalledWith(MIN_PATH, 70))
  })
})

describe('Settings search — idle compaction rows', () => {
  it('lists both rows on Chat ▸ Advanced under their config keys', () => {
    for (const key of ['session.idle_compaction', MIN_PATH]) {
      const entry = SETTINGS_REGISTRY.find(e => e.configKey === key)
      expect(entry, key).toBeDefined()
      expect(entry!.tab).toBe('chat')
      expect(entry!.params).toEqual({ sub: 'advanced' })
    }
  })

  it('finds both rows and opens Chat ▸ Advanced with the row highlighted', () => {
    const spy = vi.fn()
    const p = createSettingsProvider(spy as unknown as NavigateFunction, {
      decisionsEnabled: true, tipsEnabled: true, updateSwitches: { app: true, gateway: true },
    })
    const results = p.search('idle compaction')
    for (const [title, key] of [[SWITCH, 'session.idle_compaction'], [FIELD, MIN_PATH]]) {
      const hit = results.find(r => r.title === title)
      expect(hit, title).toBeDefined()
      spy.mockClear()
      hit!.onActivate()
      const entry = SETTINGS_REGISTRY.find(e => e.configKey === key)!
      expect(spy).toHaveBeenCalledWith(`/settings/chat/advanced?highlight=${entry.id}`)
    }
  })
})
