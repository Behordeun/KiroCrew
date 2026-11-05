/**
 * Isolated capture of the sidebar sort/filter menu's new "Remove merged PR
 * chips" action, at rest and in its two-step confirm state.
 *
 * WHY ISOLATED: the action is one menu item in the Sessions sort/filter
 * dropdown; the whole sidebar needs a gateway and an open slot that are no part
 * of what the screenshot shows. This mounts the REAL `RemoveMergedCrChips`
 * inside a real open `DropdownMenu` with the production styling, over a Redux
 * store carrying sessions that have change chips — exactly the surface the user
 * sees. Query string: ?theme=dark|light&confirm=on|off
 */
import { createRoot } from 'react-dom/client'
import { MemoryRouter } from 'react-router-dom'
import { Provider } from 'react-redux'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { configureStore } from '@reduxjs/toolkit'
import dashboardReducer from '../src/store/dashboardSlice'
import chatReducer from '../src/store/chatSlice'
import notificationsReducer from '../src/store/notificationsSlice'
import instancesReducer from '../src/store/instancesSlice'
import { initI18n } from '../src/i18n'
import { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuLabel, DropdownMenuSeparator } from '../src/components/ui/dropdown-menu'
import RemoveMergedCrChips from '../src/pages/chat-sidebar/RemoveMergedCrChips'
import '../src/index.css'

const params = new URLSearchParams(location.search)
const theme = params.get('theme') === 'light' ? 'light' : 'dark'

localStorage.setItem('mc-theme', theme)
document.documentElement.setAttribute('data-theme', theme === 'light' ? 'kiro-light' : 'kiro-dark')
document.documentElement.setAttribute('data-mode', theme)

// No gateway: answer every /api/** as empty so the store's own fixture rules.
const realFetch = globalThis.fetch.bind(globalThis)
globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
  if (url.includes('/api/')) return Promise.resolve(new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }))
  return realFetch(input, init)
}) as typeof globalThis.fetch

const initialDashboard = dashboardReducer(undefined, { type: '@@capture/init' })
const store = configureStore({
  reducer: { dashboard: dashboardReducer, chat: chatReducer, notifications: notificationsReducer, instances: instancesReducer },
  preloadedState: {
    dashboard: {
      ...initialDashboard,
      connected: true,
      slots: [
        { key: 's1', title: 'ship-dashboard', messages: 3, running: false, row_identity: 's1', created: '2026-01-01T00:00:00Z',
          source_links: [{ provider: 'github', number: 100, label: '#100', url: 'https://example.com/pull/100', state: 'merged', kind: 'change', identity: 'id-100' }], source_links_total: 1 },
      ],
    } as never,
  },
})

const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })

function Scene() {
  return (
    <div className="bg-bg text-text p-6" style={{ width: 340, minHeight: 240 }} data-capture-root>
      <DropdownMenu open>
        <DropdownMenuTrigger asChild>
          <button type="button" className="px-2 py-1 text-[12px] rounded border border-border text-muted">Sort &amp; filter</button>
        </DropdownMenuTrigger>
        <DropdownMenuContent
          forceMount
          align="start"
          sideOffset={6}
          className="min-w-[240px]"
          onCloseAutoFocus={e => e.preventDefault()}
          /* Pin the portaled content at a fixed spot so a headless browser (no
             real popper measurement) still paints it on-screen for the shot. */
          style={{ position: 'fixed', top: 48, left: 24 }}
        >
          <DropdownMenuLabel>Sort &amp; filter</DropdownMenuLabel>
          <DropdownMenuSeparator />
          <RemoveMergedCrChips />
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  )
}

initI18n('en')
createRoot(document.getElementById('root')!).render(
  <QueryClientProvider client={qc}>
    <Provider store={store}>
      <MemoryRouter>
        <Scene />
      </MemoryRouter>
    </Provider>
  </QueryClientProvider>,
)
