# Security audit: Roblox Account Manager (Rust/Tauri rewrite)

| | |
|---|---|
| Repository audited | `ZackWitAK/Roblox-Account-Manager`, a fork of `Gugas19/Roblox-Account-Manager` |
| **Pinned commit** | **`06eadcd27a51cb4f6a45df50be1634afe70bb24f`** ("4.1.13: rejoining disconnected accounts is on by default", Gugas19, 2026-10-15) |
| Audit date | 2026-10-15 |
| Scope | Everything tracked at that commit: `src/`, `ui/src/`, `tauri.conf.json`, `capabilities/`, `build.rs`, `.github/workflows/`, `tools/`, `examples/`, `tests/`, `Cargo.toml`/`Cargo.lock`, `ui/package.json`/`ui/package-lock.json` |
| Method | Manual source review, plus a vulnerability check of every locked package against the OSV database (osv.dev), which `cargo audit` and `npm audit` also draw from |

All file and line references point to the pinned commit unless they say otherwise.

## Verdict

**Nothing in this code is malicious or hidden.** No telemetry, no code that sends cookies anywhere other than Roblox, and no obfuscated or encoded payloads. The cookie storage and cryptography match the original C# app byte for byte and are implemented correctly.

There is **one high-severity finding**: the auto-updater. It lets the upstream maintainer replace the exe on your PC, and it's on by default. That's the trust you're trying to remove, so this branch removes the updater. The other findings are medium or below. They're listed with recommended fixes that need your approval before they're applied.

The fork is fit to use once the updater is removed, with the caveats under "Not verified".

## Summary of findings

| ID | Severity | Finding | Status |
|---|---|---|---|
| H1 | **High** | Auto-updater trusts the upstream maintainer's signing key, and checks and installs automatically by default | **Fixed on `hardening`**: updater removed |
| M1 | Medium | The Roblox watcher downloads regex patterns from upstream's `master` branch at runtime | **Fixed on `hardening`** |
| M2 | Medium | The Chrome for Testing download has no host allowlist and no integrity check beyond HTTPS | **Fixed on `hardening`** |
| M3 | Medium | Local web API (off by default): no Origin or Host check, and several state-changing methods need no password | **Fixed on `hardening`** |
| P1 | Policy (see note) | The login browser hides automation signals from Roblox's bot detection | **Your decision needed** |
| L1 | Low | Login passwords are captured and saved by default (`SavePasswords=true`) | Proposed, awaiting approval |
| L2 | Low | Old backup files keep the previous encryption, and cookies, for up to 8 hours after you switch to password protection | Manual step in the migration plan |
| L3 | Low | The temporary Chrome profile, which holds a live session cookie, is left in `%TEMP%` if the app crashes | Proposed, awaiting approval |
| L4 | Low | ip-api.com lookups go over plain HTTP and send Roblox server IPs to a third party | Proposed, awaiting approval |
| L5 | Low | CI actions are pinned by tag, not by commit SHA | Proposed, awaiting approval |
| L6 | Low | "Dump details" writes account information to plaintext `AccountDumps\<user>.txt` | Informational |
| I1 to I9 | Info | See below | No action needed |

---

## 1. Cookie and password handling

**Where they're stored.** `.ROBLOSECURITY` cookies (`SecurityToken`) and saved passwords (`Password`, [src/core/accounts.rs:53](src/core/accounts.rs#L53)) live only in `AccountData.json` next to the exe. Three protection modes are available ([src/core/accounts.rs:156-168](src/core/accounts.rs#L156-L168), [src/core/accounts.rs:306-335](src/core/accounts.rs#L306-L335)):

| Mode | How | Notes |
|---|---|---|
| Default | Windows DPAPI, CurrentUser scope, fixed app entropy ([src/core/crypto.rs:16-20](src/core/crypto.rs#L16-L20), [src/core/crypto.rs:107-115](src/core/crypto.rs#L107-L115)) | Any process running as your Windows user can decrypt it. That's inherent to DPAPI, and the original app worked the same way. |
| Password | Argon2i (ops 6, 128 MiB) over SHA-512(password), with a random 16-byte salt, then XSalsa20-Poly1305 with a random 24-byte nonce ([src/core/crypto.rs:22-61](src/core/crypto.rs#L22-L61)) | Sound construction. The minimum password length is only 4 characters ([src/core/accounts.rs:247](src/core/accounts.rs#L247)), so choose a long one. While the app runs, the password hash is kept in memory protected by DPAPI ([src/core/accounts.rs:174-187](src/core/accounts.rs#L174-L187)). |
| None | Plain JSON, only if a file named `NoEncryption.IUnderstandTheRisks.iautamor` exists next to the exe ([src/core/accounts.rs:156](src/core/accounts.rs#L156)) | Make sure this file is **not** in your app folder. |

Writes are atomic: a temp file, then a rename ([src/core/accounts.rs:331-333](src/core/accounts.rs#L331-L333)).

**Backups.** `AccountData.json.backup` is written at most every 8 hours ([src/core/accounts.rs:315-321](src/core/accounts.rs#L315-L321)). `AccountData.json.bak` is written when the file fails to load ([src/core/accounts.rs:228](src/core/accounts.rs#L228)), and `AccountData.json.old` when a backup is restored. Each one is a raw copy of the earlier file, so it keeps whatever encryption that file had. **L2:** if you turn on password protection, `.backup` can still be the DPAPI-protected version of the old cookies for up to 8 hours. Delete it once the password-protected file has been saved.

**Logs.** `log.txt` is recreated on every start and only records Info level and above from the app's own code ([src/platform/logging.rs:8-38](src/platform/logging.rs#L8-L38)). I checked every `log::` call and none of them logs a token, password, CSRF token, ticket, or HTTP body. Usernames do appear.

**Temp files.** The login browser uses a fresh profile in `%TEMP%\ram-browser-<pid>-<rand>` ([src/services/browser/mod.rs:77](src/services/browser/mod.rs#L77)). While it's open, Chrome stores the session cookie there, encrypted by Chrome with DPAPI. It's deleted when the browser closes ([src/services/browser/mod.rs:331-342](src/services/browser/mod.rs#L331-L342)). **L3:** it's left behind if the app is killed or crashes. Recommendation: delete stale `ram-browser-*` folders at startup.

**Clipboard.** Nothing reaches the clipboard unless you ask. Cookies, passwords, `user:pass` combos, and auth tickets are only copied when you pick "Copy ..." in the account menu ([src/commands/accounts.rs:279-312](src/commands/accounts.rs#L279-L312), [ui/src/hooks/useActions.tsx:107-115](ui/src/hooks/useActions.tsx#L107-L115)). If Windows clipboard history or cloud sync is on, copied cookies persist there.

**L1: password capture.** When you log in through the browser, the app watches the DevTools `Network.requestWillBeSent` event for the `POST https://auth.roblox.com/v2/login` body and keeps the password you typed ([src/services/browser/mod.rs:280-329](src/services/browser/mod.rs#L280-L329)). It's saved because `SavePasswords` defaults to `true` ([src/core/settings.rs:25](src/core/settings.rs#L25), [src/app.rs:286](src/app.rs#L286)). This is the original app's documented behavior and nothing is sent anywhere, but it means your account passwords sit in `AccountData.json`. **Recommendation:** default `SavePasswords` to `false`. You can also turn it off yourself in Settings before adding accounts.

**L6.** "Dump details" writes username, user ID, Robux, account age, email status, and profile JSON (no cookie) to plaintext `AccountDumps\<username>.txt` ([src/commands/accounts.rs:323-360](src/commands/accounts.rs#L323-L360)). It only runs when you ask for it.

## 2. Network calls (every outbound host)

| Host | Purpose | Where | Expected? |
|---|---|---|---|
| `www`, `auth`, `apis`, `users`, `games`, `gamejoin`, `economy`, `avatar`, `thumbnails`, `presence`, `friends`, `accountsettings`, `develop`, `clientsettings`, `assetgame` `.roblox.com` | Roblox APIs, sent with the account's cookie | [src/roblox/](src/roblox/), [src/services/launcher.rs](src/services/launcher.rs) | Yes |
| `*.rbxcdn.com`, `*.roblox.com` (images) | Avatars and game icons in the UI (CSP `img-src`) | [tauri.conf.json](tauri.conf.json) | Yes |
| `api.github.com`, `github.com` | **Auto-updater** (H1) | [src/services/updater.rs:129](src/services/updater.rs#L129), [src/services/updater.rs:150](src/services/updater.rs#L150) | **Removed** on `hardening` |
| `raw.githubusercontent.com/Gugas19/...` | **Watcher regex patterns** (M1) | [src/services/watcher.rs:54](src/services/watcher.rs#L54) | **Removed** on `hardening` (M1) |
| `googlechromelabs.github.io` and the URL it returns (normally `storage.googleapis.com`) | Chrome for Testing download, on first use (M2) | [src/services/browser/install.rs:28-89](src/services/browser/install.rs#L28-L89) | Yes, but the download URL isn't checked |
| `ip-api.com` (**plain HTTP**) | Server region lookup when you open the server list (L4). Configurable as `IPApiLink`. | [src/commands/servers.rs:99-110](src/commands/servers.rs#L99-L110), [src/core/settings.rs:30](src/core/settings.rs#L30) | Yes, as in the original |
| `discord.com` / `discordapp.com` / `ptb.` / `canary.` `/api/webhooks/` | Anti-AFK notifications. Only if you enter a webhook URL; other hosts are rejected. | [src/services/antiafk/webhook.rs:53-56](src/services/antiafk/webhook.rs#L53-L56) | Yes, opt-in |
| Roblox game servers (ICMP) | Ping column in the server list | [src/platform/ping.rs](src/platform/ping.rs) | Yes |
| `127.0.0.1:<random>` (WebSocket) | DevTools connection to the login browser | [src/services/browser/mod.rs:118-133](src/services/browser/mod.rs#L118-L133) | Yes |
| Proxies from `proxies.txt` | The login browser's traffic, if you configure them | [src/services/browser/mod.rs:42-54](src/services/browser/mod.rs#L42-L54) | Yes, opt-in |

`google.com` appears only as a spoofed `Referer` header on page navigation. No request is made to it ([src/services/browser/mod.rs:227](src/services/browser/mod.rs#L227)).

**No telemetry, analytics, crash reporting, or other hosts were found.** I searched `src/` and `ui/src/` for every `http(s)://` and `ws(s)://` literal.

**M1: remote watcher patterns.** When the Roblox Watcher is enabled, the app downloads `WatcherRegexMatches.txt` from **Gugas19's `master` branch** and its patterns override the built-in ones ([src/services/watcher.rs:52-64](src/services/watcher.rs#L52-L64), called at [src/services/watcher.rs:276](src/services/watcher.rs#L276)). That path (`RBX Alt Manager/Resources/...`) comes from the old C# repository and doesn't exist at the pinned commit, so today it returns 404 and the defaults are used. If upstream ever adds the file, they control how your watcher reads Roblox logs. The `regex` crate runs in linear time, so this can't hang the app or run code, but it can change when the watcher decides to close or rejoin clients. **Fixed on `hardening`:** the fetch is gone and only the built-in patterns are used.

**M2: Chrome for Testing download.** The app reads Google's version JSON and downloads whatever `win64` URL it lists. It doesn't check the URL's scheme or host and has no hash to verify against. It then extracts and runs `chrome.exe` ([src/services/browser/install.rs:31-89](src/services/browser/install.rs#L31-L89)). Extraction uses `zip`'s `extract`, which rejects path traversal. The trust chain is HTTPS to `googlechromelabs.github.io`. **Recommendation:** only accept `https://storage.googleapis.com/chrome-for-testing-public/` URLs, and log the version and SHA-256 of what was installed.

## 3. Auto-updater (H1, High)

What it does at the pinned commit ([src/services/updater.rs](src/services/updater.rs)):

- **Find:** on start and every 6 hours, it calls `GET https://api.github.com/repos/Gugas19/Roblox-Account-Manager/releases/latest` ([src/services/updater.rs:25](src/services/updater.rs#L25), [src/services/updater.rs:125-155](src/services/updater.rs#L125-L155), [src/services/updater.rs:362-375](src/services/updater.rs#L362-L375)). It only proceeds if the tag is newer than the running version, and the assets must be on `https://github.com/`.
- **Download:** it fetches `RobloxAccountManager-<ver>.zip` (100 MB cap) and `.zip.sig` ([src/services/updater.rs:192-227](src/services/updater.rs#L192-L227)).
- **Verify:** it checks an Ed25519 signature over `"RobloxAccountManager <ver>\n" + zip` against a **hard-coded public key `71gWjXxo...UPQ=`** ([src/services/updater.rs:27](src/services/updater.rs#L27), [src/services/updater.rs:95-113](src/services/updater.rs#L95-L113)). Including the version stops an old release being replayed as a newer one. The signature is checked again at install time.
- **Install:** at the next start, before anything else runs ([src/lib.rs:89-92](src/lib.rs#L89-L92)), it swaps in only `RobloxAccountManager.exe` and `ram-cli.exe`, matched by file name with paths ignored and a 200 MB per-file cap ([src/services/updater.rs:29](src/services/updater.rs#L29), [src/services/updater.rs:230-333](src/services/updater.rs#L230-L333)). Then it starts the new exe.
- **Defaults:** `Updates.Check=true` and `Updates.AutoInstall=true` ([src/core/settings.rs:61-63](src/core/settings.rs#L61-L63)). It's skipped only when the exe runs from a path containing a `target` folder ([src/services/updater.rs:78-80](src/services/updater.rs#L78-L80)).
- **Key origin:** the private key is generated on the maintainer's PC by `examples/sign-release.rs` and stored in `%USERPROFILE%\.roblox-account-manager\release-signing-key.txt`. Releases are signed locally by `tools/release.ps1`. No key or secret is in the repo or in CI.

The mechanism itself is well built. **The problem is who it trusts.** A build of your fork would silently replace itself with whatever the upstream maintainer, or anyone who gets their key, signs. Both exes run with full access to your decrypted cookies. That's remote code execution controlled by a third party, and it's on by default.

**What was done (task 3, preferred option):** the updater is removed completely on the `hardening` branch. See "Changes on the `hardening` branch" below.

## 4. Local web API and `ram-cli`

**Web API** ([src/services/webserver.rs](src/services/webserver.rs)): a port of the original's API.

- **Off by default** (`Developer.EnableWebServer=false`, [src/core/settings.rs:46](src/core/settings.rs#L46)). When enabled, it binds to `127.0.0.1:7963`, or to `0.0.0.0` only if `AllowExternalConnections` is on ([src/services/webserver.rs:32-34](src/services/webserver.rs#L32-L34)). Non-loopback clients are also rejected per request unless that setting is on ([src/services/webserver.rs:98](src/services/webserver.rs#L98)). It uses plain HTTP.
- **Authentication:** an optional password of at least 6 characters, passed as `?Password=` in the URL and compared in non-constant time ([src/services/webserver.rs:109-111](src/services/webserver.rs#L109-L111)). It's required for `GetCookie`, `GetAccounts`, `LaunchAccount`, `FollowUser`, and `KillProcess` ([src/services/webserver.rs:123](src/services/webserver.rs#L123)), and for including cookies in `GetAccountsJson` ([src/services/webserver.rs:142](src/services/webserver.rs#L142)). `GetCookie`, `GetAccounts`, `LaunchAccount`, and account editing also need their own setting, all off by default ([src/core/settings.rs:49-57](src/core/settings.rs#L49-L57)).
- **M3:** there's no `Origin` or `Host` check ([src/services/webserver.rs:67-83](src/services/webserver.rs#L67-L83)). With the server on, **any web page you visit** can send requests to `http://127.0.0.1:7963/...`. It can't read the responses, but the side effects still happen, and a DNS-rebinding page could also read the unprotected responses. These methods need **no password** unless `EveryRequestRequiresPassword` is on:
  - `ImportCookie`: adds an attacker's account to your list ([src/services/webserver.rs:162-166](src/services/webserver.rs#L162-L166))
  - `SetAvatar`: changes an account's avatar, and also ignores `AllowAccountEditing` ([src/services/webserver.rs:315-322](src/services/webserver.rs#L315-L322))
  - `BlockUser`, `UnblockUser`, `UnblockEveryone`, `SetServer`, `SetRecommendedServer`, `GetCSRFToken`, `GetAlias`, `GetDescription`, `GetField` ([src/services/webserver.rs:214-294](src/services/webserver.rs#L214-L294))

  These match the original C# app's behavior. **Recommendation:** reject requests that carry an `Origin` header or whose `Host` isn't `localhost` or `127.0.0.1`. Require the password for every state-changing method, and put `SetAvatar` behind `AllowAccountEditing`. **If you don't use the web API, leave it off.**

**`ram-cli`** ([src/cli/](src/cli/)) talks to the open app over a named pipe, `\\.\pipe\RobloxAccountManager.cli.<hash of folder>` ([src/cli/pipe.rs:23-28](src/cli/pipe.rs#L23-L28)):

- `reject_remote_clients(true)` is set ([src/cli/pipe.rs:41](src/cli/pipe.rs#L41)). The client checks that the pipe's server runs as the same Windows user before sending anything, which guards against pipe squatting ([src/cli/pipe.rs:106-108](src/cli/pipe.rs#L106-L108), [src/cli/pipe.rs:130-160](src/cli/pipe.rs#L130-L160)).
- The server doesn't check who the client is. It relies on Windows' default pipe DACL, under which other non-admin users only get read access. Informational.
- Commands: `list`, `join`, `follow`, `close`, `import`, `antiafk`, `status`, `open`, `fps` (and `update`, removed on `hardening`). **None of them output cookies.** `list --json` uses `AccountView`, which has no token field ([src/app.rs:102-120](src/app.rs#L102-L120)).
- When the app isn't open, `ram-cli` opens the accounts file itself and reads the password from the `RAM_PASSWORD` environment variable or a prompt ([src/cli/mod.rs:240-246](src/cli/mod.rs#L240-L246)). Avoid leaving `RAM_PASSWORD` set permanently.

## 5. Process, input and file access

| What | Where | Default |
|---|---|---|
| Starts Chrome for Testing with DevTools on a random localhost port | [src/services/browser/mod.rs:76-172](src/services/browser/mod.rs#L76-L172) | When you add or open an account |
| Opens `roblox-player:` links, URLs, and folders via `ShellExecuteExW`. Only built-in targets, never arbitrary input ([src/commands/settings.rs:80-91](src/commands/settings.rs#L80-L91)) | [src/platform/win.rs:226-246](src/platform/win.rs#L226-L246) | On use |
| **Simulated keystrokes** (`SendInput`) into Roblox windows for Anti-AFK | [src/services/antiafk/input.rs:59-61](src/services/antiafk/input.rs#L59-L61) | Only when you start Anti-AFK (`AutoStart=false`) |
| Sends `WM_CLOSE` to Roblox windows (watcher limits, stale clients) | [src/platform/win.rs:207](src/platform/win.rs#L207) | Watcher is opt-in |
| Lowers priority and enables power throttling of Roblox processes | [src/services/antiafk/efficiency.rs](src/services/antiafk/efficiency.rs) | Opt-in (`Efficiency=false`) |
| Holds `ROBLOX_singletonMutex` so several Roblox clients can run | [src/app.rs:264-280](src/app.rs#L264-L280) | **On** (`EnableMultiRbx=true`), as in the original |
| Writes `ClientSettings\ClientAppSettings.json` in Roblox's install folder (FPS cap, custom settings) | [src/services/launcher.rs:93-136](src/services/launcher.rs#L93-L136) | Only when FPS unlock or a custom file is set |
| Reads Roblox's logs in `%LOCALAPPDATA%\Roblox\logs`, Roblox process command lines, and `HKCR\roblox\DefaultIcon` | [src/services/watcher.rs:67](src/services/watcher.rs#L67), [src/services/antiafk/rejoin.rs:47](src/services/antiafk/rejoin.rs#L47), [src/platform/win.rs:310](src/platform/win.rs#L310) | Watcher, rejoin, launcher |
| Writes outside the app folder: `%LOCALAPPDATA%\RobloxAccountManager\Chrome`, `%TEMP%\ram-browser-*`, `HKCU\...\Run` (only when "Run on startup" is on, [src/platform/win.rs:286-305](src/platform/win.rs#L286-L305)), and Roblox's `ClientSettings` (above) | | |
| `BrowserConfig.json` and an `extension\` folder next to the exe can add Chrome arguments, load an extension, and run scripts in the login page | [src/services/browser/mod.rs:80-105](src/services/browser/mod.rs#L80-L105), [src/services/browser/mod.rs:161-180](src/services/browser/mod.rs#L161-L180) | Only if those files exist. Keep the app folder writable only by you. |

No code reads other applications' data: no browser cookie stores, Discord tokens, or similar. No code injects into other processes: no `WriteProcessMemory`, `CreateRemoteThread`, or DLL injection.

Anti-AFK input, multiple Roblox clients, and FPS unlocking may break Roblox's Terms of Use. That's your call. It's mentioned because those are features of the app, not hidden behavior.

### P1: automation-signal masking (your decision)

The login browser is started with `--disable-blink-features=AutomationControlled` ([src/services/browser/mod.rs:87](src/services/browser/mod.rs#L87)). It also injects `Object.defineProperty(navigator, 'webdriver', { get: () => undefined })` into every page ([src/services/browser/mod.rs:154](src/services/browser/mod.rs#L154)) and sends a fake `Referer: https://google.com/` ([src/services/browser/mod.rs:227](src/services/browser/mod.rs#L227)). The code comment says why: "Roblox shows more captchas to automated browsers".

None of this solves the "Press and hold" challenge. You still do that yourself, and nothing in the code clicks, holds, or solves challenges. But it does **hide from Roblox's bot detection that the browser is being driven by a program**, which conflicts with your "no evasion" constraint. It's already in the upstream code, not something added here, so I've left it as is for you to decide:

- **Remove it** (consistent with your constraint). The DevTools-controlled browser will then show `navigator.webdriver === true`, and Roblox may challenge you more often or block the login. In that case, cookie import is the fallback.
- **Keep it** (upstream behavior).

## 6. Build-time and configuration risks

- **[build.rs](build.rs):** only `tauri_build::build()`.
- **[tauri.conf.json](tauri.conf.json):** CSP is `default-src 'self'`. Scripts can only come from the bundled UI, there's no `unsafe-eval`, `connect-src` is limited to Tauri IPC, and images come from Roblox CDNs. No remote URLs are loaded in the app window. `withGlobalTauri: true` lets any script in the window call the app's commands, including `copy_text` with `kind: "token"`, which is acceptable given the strict CSP. Bundling is disabled. (I1)
- **[capabilities/default.json](capabilities/default.json):** only `core:default` for the `main` window. **No shell, filesystem, HTTP, or updater plugins.** The app's own `#[tauri::command]`s are the whole surface. (I2)
- **[.github/workflows/ci.yml](.github/workflows/ci.yml):** `permissions: contents: read`, no secrets, no release or publish steps. It builds, runs clippy, runs tests, and checks translations. **L5:** third-party actions are pinned by tag (`actions/checkout@v5`, `actions/setup-node@v5`, `actions/setup-python@v6`, `Swatinem/rust-cache@v2`), not by commit SHA. Recommendation: pin them to SHAs, or just don't rely on this CI for anything you trust.
- **[tools/release.ps1](tools/release.ps1):** builds, tests, optionally Authenticode-signs, zips, and signs for the updater. Nothing is uploaded. Updated on `hardening` to drop the updater signing.
- **[RAMAccount.lua](RAMAccount.lua):** an in-game Lua helper for the web API, not executed by the app.

## 7. Dependencies

**Rust** ([Cargo.toml](Cargo.toml), 571 registry packages in [Cargo.lock](Cargo.lock)): every direct dependency is a mainstream crate (tauri 2, tokio, reqwest with native-tls, serde, argon2, crypto_secretbox, ed25519-dalek, zip, sysinfo, winreg, windows, rfd, tiny_http, tokio-tungstenite). There are no git or path dependencies, and every source is `registry+https://github.com/rust-lang/crates.io-index`.

**npm** ([ui/package.json](ui/package.json), 484 packages in [ui/package-lock.json](ui/package-lock.json)): every `resolved` URL is on `https://registry.npmjs.org/`, **no package has an install script** (`hasInstallScript`), and all have `integrity` hashes.

**OSV results** for every locked version, checked 2026-10-15:

| Package | Advisory | Assessment |
|---|---|---|
| `glib` 0.18.5 (crate) | RUSTSEC-2024-0429 / GHSA-wrw7-89jp-8q8g, unsoundness in `VariantStrIter` | Comes in through Tauri's Linux (GTK) backend. **Not compiled on Windows.** Info. |
| `proc-macro-error` 1.0.4 (crate) | RUSTSEC-2024-0370, unmaintained | Build-time proc-macro only. Info. |
| `braces` 3.0.3 (npm, dev) | GHSA-vfj7-8cjw-p6xm, stack-exhaustion DoS on nested patterns | Dev and build tooling only, not shipped. Info. |

**Unusual or new packages:**

- **`cn` 0.4.0 (npm)** replaces the usual `clsx` + `tailwind-merge` helper and is imported by every UI component. It's very new: published 2026-09-22, about 3 weeks before this audit. On the npm registry, the old 2013 `cn` name now belongs to the shadcn maintainer (`m@shadcn.com`, repository `shadcn-ui/cn`). 0.4.0 was published by GitHub Actions OIDC with **SLSA provenance**. I downloaded the tarball and its SHA-512 matches the lockfile. It has no dependencies or install scripts, and its `dist/` code contains no `fetch`, XHR, WebSocket, `eval`, `Function`, `child_process`, `process.env`, or Tauri access. **Assessed as legitimate.** (I3)
- `typescript ~6.0.2`, `vite ^8.3.0`, `lucide-react ^1.55`, `oxlint`: recent major versions, all from their usual publishers. Not individually reviewed.
- Rust: nothing unusual. `ed25519-dalek` and its exclusive dependencies are removed on `hardening` together with the updater.

## 8. Changes on the `hardening` branch

1. **This audit** (`AUDIT.md`).
2. **Updater removed** (H1):
   - Deleted [src/services/updater.rs](src/services/updater.rs), [src/commands/updates.rs](src/commands/updates.rs), and [examples/sign-release.rs](examples/sign-release.rs).
   - Removed the startup install, cleanup, and periodic check, and the `--updated`/`--after` restart handling ([src/lib.rs](src/lib.rs)).
   - Removed the `App.update` state, the three Tauri commands, the `ram-cli update` command, and the `[Updates]` setting defaults.
   - UI: deleted `UpdatePill.tsx`, `UpdatesSection.tsx`, and `useUpdate.ts`, and removed their uses in `TopBar`, `ProtectionScreen`, `SettingsDialog`, `api.ts`, and `types.ts`.
   - `ed25519-dalek` removed from `Cargo.toml`, and its 10 exclusive packages removed from `Cargo.lock` by hand, with no other version changes.
   - Tests: the update-settings UI test and the CLI `update` check now assert that `update` is an unknown command. `tests/update.mjs` now checks that no updater code or GitHub release endpoint is left in the sources or in a built exe.
   - `tools/release.ps1` no longer builds or runs the signing tool.
   - An existing `[Updates]` section in `RAMSettings.ini` is now ignored.
3. **README** rewritten for this fork.
4. **M1:** the watcher uses only its built-in patterns; the download from upstream's GitHub is gone ([src/services/watcher.rs](src/services/watcher.rs)).
5. **M2:** the Chrome for Testing version must be four numbers and the download URL must be exactly `https://storage.googleapis.com/chrome-for-testing-public/<version>/win64/chrome-win64.zip`. The download is capped at 600 MB and its size and SHA-256 are written to `log.txt` ([src/services/browser/install.rs](src/services/browser/install.rs)).
6. **M3:** the web API refuses requests carrying `Origin` or a `Sec-Fetch-Site` other than `none`, refuses a `Host` other than `localhost`/`127.0.0.1`/`[::1]` unless external connections are allowed, requires the password for every state-changing method and `GetCSRFToken`, and puts `SetAvatar` behind `AllowAccountEditing` ([src/services/webserver.rs](src/services/webserver.rs)). Scripts that call these methods must now send the password.

## Not verified

- **Nothing was compiled or run.** This environment has no Rust, Node, or npm (Python is only the Windows Store stub). The updater removal was checked by reading every reference, not by `cargo build`, `clippy`, `tsc`, or the test suites. The first build on your machine is the real check.
- `cargo audit` and `npm audit` weren't run. The OSV query above is a substitute that uses the same advisory data.
- Transitive dependencies (about 1,055 packages) weren't read, apart from `cn`. Tauri, WebView2, and Chrome for Testing are trusted as their vendors publish them.
- Whether the "Press and hold" challenge passes in Chrome for Testing is unknown. It can only be tested by hand.
- Whether the Chrome for Testing JSON currently points at `storage.googleapis.com` wasn't checked at runtime.
- Upstream's GitHub release binaries weren't compared with the source. Don't use them; build from source.
- The behavior of the Roblox APIs and the `roblox-player:` launcher wasn't verified against the live services.
