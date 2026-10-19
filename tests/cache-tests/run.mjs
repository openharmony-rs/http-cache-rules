// Runs the HTTP caching tests of https://cache-tests.fyi/ in browser-cache mode through
// proxy.rs, a private cache that makes every RFC 9111 decision with this crate, and compares
// each test's result with expected.json. With `--update`, rewrites expected.json instead.
//
// Usage: node run.mjs <cache-tests checkout> <proxy binary> [--update]
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'

const [suiteDir, proxyBinary, flag] = process.argv.slice(2)
const originPort = 18000
const proxyPort = 18001
const expectedFile = path.join(import.meta.dirname, 'expected.json')

async function waitForListener (port) {
  for (let attempt = 0; attempt < 100; attempt++) {
    const connected = await new Promise(resolve => {
      const socket = net.connect(port, '127.0.0.1', () => {
        socket.end()
        resolve(true)
      })
      socket.on('error', () => resolve(false))
    })
    if (connected) return
    await sleep(100)
  }
  throw new Error(`nothing listens on port ${port}`)
}

const children = [
  spawn(process.execPath, ['test-engine/server/server.mjs'], {
    cwd: suiteDir,
    env: {
      ...process.env,
      npm_config_protocol: 'http',
      npm_config_port: String(originPort),
      npm_config_pidfile: path.join(os.tmpdir(), 'http-cache-rules-cache-tests.pid')
    },
    stdio: ['ignore', 'ignore', 'inherit']
  }),
  spawn(proxyBinary, [`127.0.0.1:${proxyPort}`, `127.0.0.1:${originPort}`], {
    stdio: ['ignore', 'ignore', 'inherit']
  })
]

try {
  await waitForListener(originPort)
  await waitForListener(proxyPort)
  const suite = file => import(path.resolve(suiteDir, file))
  const { runTests, getResults } = await suite('test-engine/client/runner.mjs')
  const { determineTestResult, resultTypes } = await suite('test-engine/lib/results.mjs')
  const tests = (await suite('tests/index.mjs')).default

  // Fetch appends `Cache-Control: max-age=0` for the 'no-cache' cache mode (HTTP-network-or-cache
  // fetch); Node's fetch has no HTTP cache, so the request carries it instead.
  for (const group of tests) {
    for (const test of group.tests) {
      for (const request of test.requests) {
        if (request.cache === 'no-cache') {
          request.request_headers = (request.request_headers || []).concat([['Cache-Control', 'max-age=0']])
          delete request.cache
        }
      }
    }
  }

  await runTests(tests, true, `http://localhost:${proxyPort}`)
  const results = getResults()
  const names = new Map(Object.entries(resultTypes).map(([name, type]) => [type, name]))
  const actual = {}
  for (const id of Object.keys(results).sort()) {
    actual[id] = names.get(determineTestResult(tests, id, results))
  }
  const counts = {}
  for (const result of Object.values(actual)) counts[result] = (counts[result] || 0) + 1
  console.log(`${Object.keys(actual).length} tests: ${JSON.stringify(counts)}`)

  if (flag === '--update') {
    fs.writeFileSync(expectedFile, JSON.stringify(actual, null, 2) + '\n')
    console.log(`wrote ${expectedFile}`)
  } else {
    const expected = JSON.parse(fs.readFileSync(expectedFile, 'utf8'))
    const ids = [...new Set([...Object.keys(expected), ...Object.keys(actual)])].sort()
    const changed = ids.filter(id => expected[id] !== actual[id])
    for (const id of changed) {
      const detail = Array.isArray(results[id]) ? ` (${results[id].slice(1).join(' ')})` : ''
      console.log(`${id}: expected ${expected[id] ?? 'not run'}, got ${actual[id] ?? 'not run'}${detail}`)
    }
    if (changed.length > 0) {
      console.log(`${changed.length} results differ from ${expectedFile}; run with --update if the change is intended`)
      process.exitCode = 1
    }
  }
} finally {
  for (const child of children) child.kill()
}
