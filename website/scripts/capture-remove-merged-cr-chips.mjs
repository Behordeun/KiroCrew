/**
 * Screenshot of the sidebar sort/filter menu's new "Remove merged PR chips"
 * action. Gateway-free, in-process vite dev server (so no separate server
 * command), light AND dark; shoots the open menu content.
 *
 * Usage: node scripts/capture-remove-merged-cr-chips.mjs [outDir]
 */
import { chromium } from 'playwright'
import { mkdirSync } from 'node:fs'
import { createServer } from 'vite'
import { chromiumExecutable } from './lib/chromium-executable.mjs'

const OUT = process.argv[2] || '../temp-screenshots/30005'
mkdirSync(OUT, { recursive: true })

const vite = await createServer({
  configFile: new URL('../vite.config.ts', import.meta.url).pathname,
  server: { port: 0 },
  logLevel: 'error',
})
await vite.listen()
const BASE = vite.resolvedUrls.local[0].replace(/\/$/, '')
console.log(`dev server on ${BASE}`)

const { LD_LIBRARY_PATH: _mise, ...browserEnv } = process.env
const browser = await chromium.launch({ executablePath: chromiumExecutable(), env: browserEnv })
let failed = false

try {
  for (const theme of ['dark', 'light']) {
    const context = await browser.newContext({ deviceScaleFactor: 2, viewport: { width: 360, height: 240 } })
    const page = await context.newPage()
    page.on('pageerror', e => { console.log(`FAIL pageerror — ${e.message}`); failed = true })
    await page.goto(`${BASE}/capture/remove-merged-cr-chips-menu.html?theme=${theme}`, { waitUntil: 'domcontentloaded' })
    const item = page.getByTestId('remove-merged-cr-chips')
    await item.waitFor({ state: 'visible', timeout: 30_000 })
    const label = (await item.textContent())?.trim()
    const ok = label === 'Remove merged PR chips'
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${theme}: item label = ${JSON.stringify(label)}`)
    if (!ok) failed = true
    // The menu is portaled and fixed-positioned at (24,48); clip the viewport
    // to the region it occupies rather than screenshotting the Radix node,
    // whose own box can be zero-sized under a headless popper.
    await page.screenshot({ path: `${OUT}/remove-merged-cr-chips-menu-${theme}.png`, clip: { x: 16, y: 40, width: 300, height: 150 } })
    console.log(`wrote ${OUT}/remove-merged-cr-chips-menu-${theme}.png`)
    await context.close()
  }
} finally {
  await browser.close()
  await vite.close()
}

process.exit(failed ? 1 : 0)
