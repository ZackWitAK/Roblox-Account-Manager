// No auto updater in this fork: node tests/update.mjs   (best after npm --prefix ui run build and cargo build --release)
//
// The upstream updater installed whatever the upstream maintainer signed. This fork removed it (see AUDIT.md, H1),
// and this test keeps it out:
// - the sources, the Tauri config and the dependency lists have no updater code, endpoint or plugin
// - the built exes and the built interface (when present) don't contain the GitHub releases endpoint either
// Never runs the app, never touches the network.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

// what only an updater needs: the releases API, the update commands, the restart flag, the signing key and plugins
const MARKERS = ['api.github.com', 'releases/latest', 'update_check', 'update_restart', 'update_status', '--updated', 'release-signing-key', 'ed25519', 'plugin-updater', 'tauri-plugin-updater', 'install_staged']

let failed = 0
async function test(name, run) {
  try {
    await run()
    console.log(`  ok  ${name}`)
  } catch (e) {
    failed++
    console.log(`  FAIL ${name}\n       ${String(e.message ?? e).replace(/\n/g, '\n       ')}`)
  }
}

function files(dir, extensions) {
  if (!fs.existsSync(dir)) return []
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) return entry.name === 'node_modules' ? [] : files(full, extensions)
    return extensions.some((ext) => entry.name.endsWith(ext)) ? [full] : []
  })
}

function found(file, text) {
  return MARKERS.filter((m) => text.includes(m)).map((m) => `${path.relative(root, file)}: "${m}"`)
}

await test('the sources have no updater', () => {
  const sources = [
    ...files(path.join(root, 'src'), ['.rs']),
    ...files(path.join(root, 'ui', 'src'), ['.ts', '.tsx']),
    ...files(path.join(root, 'capabilities'), ['.json']),
    ...['tauri.conf.json', 'Cargo.toml', 'ui/package.json'].map((f) => path.join(root, f)),
  ]
  const hits = sources.flatMap((f) => found(f, fs.readFileSync(f, 'utf8')))
  if (hits.length) throw new Error(hits.join('\n'))
  for (const gone of ['src/services/updater.rs', 'src/commands/updates.rs', 'examples/sign-release.rs']) {
    if (fs.existsSync(path.join(root, gone))) throw new Error(`${gone} is back`)
  }
})

await test('the lock files have no updater or signing crates', () => {
  const lock = fs.readFileSync(path.join(root, 'Cargo.lock'), 'utf8')
  const crates = ['ed25519-dalek', 'tauri-plugin-updater', 'minisign-verify'].filter((c) => lock.includes(`name = "${c}"`))
  if (crates.length) throw new Error(`Cargo.lock has ${crates.join(', ')}`)
  const npm = fs.readFileSync(path.join(root, 'ui', 'package-lock.json'), 'utf8')
  if (npm.includes('@tauri-apps/plugin-updater')) throw new Error('ui/package-lock.json has @tauri-apps/plugin-updater')
})

await test('built exes and interface have no updater (skipped when not built)', () => {
  const built = [
    ...['release', 'debug'].flatMap((profile) => ['RobloxAccountManager.exe', 'ram-cli.exe'].map((exe) => path.join(root, 'target', profile, exe))),
    ...files(path.join(root, 'ui', 'dist'), ['.js']),
  ].filter((f) => fs.existsSync(f))
  if (!built.length) {
    console.log('       nothing built yet, only the sources were checked')
    return
  }
  // the exe holds its strings as UTF-8, latin1 keeps every byte so includes() finds them
  const hits = built.flatMap((f) => found(f, fs.readFileSync(f).toString('latin1')).filter((h) => !h.endsWith('"ed25519"')))
  if (hits.length) throw new Error(hits.join('\n'))
  console.log(`       checked ${built.map((f) => path.relative(root, f)).join(', ')}`)
})

console.log(`\n${3 - failed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
