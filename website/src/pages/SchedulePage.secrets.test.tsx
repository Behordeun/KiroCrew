import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api/client'
import type { CronJob } from '../types'
import { renderWithProviders } from '../test/helpers'
import { JobSecretsPanel } from './SchedulePage'

vi.mock('../api/client', () => ({
  api: {
    cronSecretsGrant: vi.fn(),
    secretsList: vi.fn(),
  },
}))

// SimpleSelect is Radix-backed on non-touch devices; driving its portal menu in
// jsdom tests the library, not this panel. A native stand-in keeps the test on
// the panel's own wiring (options in, value out).
vi.mock('../components/SimpleSelect', () => ({
  default: ({
    options,
    value,
    onChange,
    'aria-label': ariaLabel,
  }: {
    options: string[]
    value: string
    onChange: (v: string) => void
    'aria-label'?: string
  }) => (
    <select aria-label={ariaLabel} value={value} onChange={e => onChange(e.target.value)}>
      <option value="" />
      {options.map(o => (
        <option key={o} value={o}>
          {o}
        </option>
      ))}
    </select>
  ),
}))

const BASE_JOB: CronJob = {
  id: 'abc12345',
  name: 'escalation-watch',
  message: 'args',
  enabled: true,
  schedule: 'every 3600s',
  last_status: 'ok',
  command: 'echo hi',
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api.secretsList).mockResolvedValue({ names: ['slack-sandbox', 'jira-token'] })
  vi.mocked(api.cronSecretsGrant).mockResolvedValue({ ok: true })
})

describe('JobSecretsPanel', () => {
  it('renders the pending request and approves through the grant endpoint', async () => {
    const onSaved = vi.fn()
    renderWithProviders(
      <JobSecretsPanel
        job={{ ...BASE_JOB, secret_env_pending: { MY_SANDBOX_TOKEN: 'slack-sandbox' } }}
        onSaved={onSaved}
      />,
    )
    // The banner shows names only — env key and vault name.
    expect(screen.getByText(/MY_SANDBOX_TOKEN/)).toBeInTheDocument()
    expect(screen.getByText('Agent requested secrets')).toBeInTheDocument()
    await userEvent.click(screen.getByText('Approve'))
    await waitFor(() =>
      expect(api.cronSecretsGrant).toHaveBeenCalledWith('abc12345', {
        approve_pending: true,
        expected_secret_env: { MY_SANDBOX_TOKEN: 'slack-sandbox' },
        expected_ts: undefined,
      }),
    )
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
  })

  it('denies a pending request through the grant endpoint', async () => {
    renderWithProviders(
      <JobSecretsPanel
        job={{ ...BASE_JOB, secret_env_pending: { MY_SANDBOX_TOKEN: 'slack-sandbox' } }}
        onSaved={vi.fn()}
      />,
    )
    await userEvent.click(screen.getByText('Deny'))
    await waitFor(() =>
      expect(api.cronSecretsGrant).toHaveBeenCalledWith('abc12345', {
        deny_pending: true,
        expected_secret_env: { MY_SANDBOX_TOKEN: 'slack-sandbox' },
      }),
    )
  })

  it('shows the active grant read-only and revokes it whole', async () => {
    renderWithProviders(
      <JobSecretsPanel job={{ ...BASE_JOB, secret_env: { OLD_TOKEN: 'jira-token' } }} onSaved={vi.fn()} />,
    )
    expect(screen.queryByText('Agent requested secrets')).not.toBeInTheDocument()
    await userEvent.click(screen.getByText('Vault secrets'))
    expect(screen.getByText('OLD_TOKEN')).toBeInTheDocument()
    // Direct grant editing is gone: the request->approve flow is the only
    // mint path, so the panel offers display + whole-grant revoke only.
    expect(screen.queryByText('Save grants')).not.toBeInTheDocument()
    await userEvent.click(screen.getByText('Revoke all secrets'))
    await waitFor(() =>
      expect(api.cronSecretsGrant).toHaveBeenCalledWith('abc12345', { secret_env: {} }),
    )
  })
})
