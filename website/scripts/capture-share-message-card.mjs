/**
 * Screenshot harness + behavior check for SHARE MESSAGE AS CARD.
 *
 * Drives the REAL built SPA (website/dist): opens a finished chat, clicks the
 * new share action on the assistant reply, and verifies the dialog renders
 * the branded card with the Q&A pair and the prefilled caption. Then plants
 * an AWS-key-shaped string in the caption and verifies the sensitive-content
 * banner appears. Exits non-zero when either check fails. Nothing in CI runs
 * this file — the CI-enforced half lives in ShareMessageModal.test.tsx.
 *
 * Usage: node scripts/capture-share-message-card.mjs [outDir]
 */
import { chromium } from 'playwright'
import { mkdirSync } from 'node:fs'
import { serveDist } from './lib/serve-dist.mjs'
import { logPageProblems, stubDashboardApi, json } from './lib/stub-dashboard-api.mjs'

const OUT = process.argv[2] || '../temp-screenshots/share-message-card'
const SLOT = 'chat-share'
const PROJECT = '/home/user/workspace/service'

mkdirSync(OUT, { recursive: true })

const ANSWER = [
  'Overnight batch done: scanned 47 new issues, triaged 3 as auto-fixable and dispatched all of them.',
  '#4881 opened PR #7202 (CI all green, awaiting review) and #5104 opened PR #7205 (Windows shard still running).',
  'Nobody was at the keyboard for any of it.',
].join('\n\n')

const slots = [{
  key: SLOT,
  title: 'Nightly issue triage',
  running: false,
  last_message: ANSWER,
  messages: 2,
  agent: 'kirocrew',
  memory_mode: 'persistent',
  project: PROJECT,
  folder_id: '',
  modified: Math.floor(Date.now() / 1000),
  source_links: [],
  source_links_total: 0,
}]

const detail = {
  running: false,
  has_more: false,
  total: 2,
  queue: [],
  project: PROJECT,
  messages: [
    { role: 'user', ts: Date.now() / 1000 - 600, content: 'How did the overnight run go?' },
    { role: 'assistant', ts: Date.now() / 1000 - 580, content: ANSWER },
  ],
}

async function main() {
  const { srv, base } = await serveDist()
  const browser = await chromium.launch()
  const context = await browser.newContext({
    viewport: { width: 1400, height: 950 },
    deviceScaleFactor: 2,
    locale: 'en-US',
  })

  const extra = async (path, route) => {
    if (path.startsWith('/api/chat/slots/')) { await json(route, detail); return true }
    return false
  }

  const page = await context.newPage()
  logPageProblems(page)
  await stubDashboardApi(page, { slots, theme: 'dark', extra })
  await page.addInitScript(slot => { localStorage.setItem('mc-active-slot', slot) }, SLOT)
  await page.goto(base + '/', { waitUntil: 'domcontentloaded' })
  await page.waitForTimeout(2000)

  // Share lives in the overflow menu below the hover action row (the row
  // itself is capped by the two-action rule).
  await page.locator('.msg-content').last().hover()
  const moreBtn = page.getByTestId('assistant-more-actions')
  await moreBtn.waitFor({ timeout: 10000 })
  await moreBtn.click()
  const shareItem = page.getByTestId('share-message')
  await shareItem.waitFor({ timeout: 5000 })
  await shareItem.click()

  const card = page.getByTestId('share-card')
  await card.waitFor({ timeout: 10000 })
  await page.waitForTimeout(600)

  const cardText = await card.innerText()
  const pairedQuestion = cardText.includes('How did the overnight run go?')
  const hasExcerpt = cardText.includes('scanned 47 new issues')
  await page.screenshot({ path: `${OUT}/1-share-dialog-default.png` })
  console.log('wrote', `${OUT}/1-share-dialog-default.png`)

  // Plant a credential-shaped string; the pre-share banner must appear.
  const caption = page.locator('#share-caption')
  await caption.fill('Deployed with AKIAIOSFODNN7EXAMPLE — look how fast')
  const alert = page.locator('[role="alert"]')
  await alert.waitFor({ timeout: 5000 })
  await page.waitForTimeout(300)
  await page.screenshot({ path: `${OUT}/2-sensitive-warning.png` })
  console.log('wrote', `${OUT}/2-sensitive-warning.png`)

  const alertText = await alert.innerText()

  // The card's brand mark is a CSS-mask glyph; prove it survives the
  // html-to-image export by capturing the REAL downloaded PNG.
  const downloadPromise = page.waitForEvent('download', { timeout: 15000 })
  await page.getByTestId('share-download').click()
  const download = await downloadPromise
  await download.saveAs(`${OUT}/3-exported-card.png`)
  console.log('wrote', `${OUT}/3-exported-card.png`)

  console.log({ pairedQuestion, hasExcerpt, warned: alertText.length > 0 })
  await browser.close()
  srv.close()

  if (!pairedQuestion || !hasExcerpt || !alertText.includes('AWS')) {
    console.error('FAIL: share dialog did not render the expected card or warning')
    process.exit(1)
  }
}

main().catch(err => { console.error(err); process.exit(1) })
