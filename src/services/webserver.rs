//! The local web API (port of AccountManager.SendResponse), same methods, parameters and answers.

use crate::app::{app, App};
use crate::services::launcher::{self, JoinOptions};
use std::collections::HashMap;
use std::sync::Arc;
use std::thread::JoinHandle;

pub struct Handle {
    server: Arc<tiny_http::Server>,
    thread: Option<JoinHandle<()>>,
    pub address: String,
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Starts the server with the current settings (or stops it), every setting applies right away
pub fn restart(app: &App) -> anyhow::Result<Option<String>> {
    *app.web_server.lock().unwrap() = None;

    if !app.setting_bool("Developer", "EnableWebServer") {
        return Ok(None);
    }

    let port = app.setting_i64("WebServer", "WebServerPort", 7963);
    let external = app.setting_bool("WebServer", "AllowExternalConnections");
    let address = format!("{}:{}", if external { "0.0.0.0" } else { "127.0.0.1" }, port);

    let server = Arc::new(tiny_http::Server::http(&address).map_err(|e| anyhow::anyhow!("Failed to start webserver!\n\n{e}"))?);
    let worker = server.clone();

    let thread = std::thread::spawn(move || {
        for request in worker.incoming_requests() {
            std::thread::spawn(move || respond(request));
        }
    });

    *app.web_server.lock().unwrap() = Some(Handle { server, thread: Some(thread), address: address.clone() });
    Ok(Some(address))
}

pub struct Reply {
    pub status: u16,
    pub body: String,
}

fn query(url: &str) -> HashMap<String, String> {
    url.split_once('?')
        .map(|(_, q)| {
            q.split('&')
                .filter_map(|pair| {
                    let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                    Some((urlencoding::decode(k).ok()?.into_owned(), urlencoding::decode(&v.replace('+', " ")).ok()?.into_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Methods that change an account, add one, or hand out its CSRF token: they need the web server password like the
/// cookie and launch methods always did (AUDIT.md, M3)
const PROTECTED: &[&str] = &[
    "GetCookie", "GetAccounts", "LaunchAccount", "FollowUser", "KillProcess", "ImportCookie", "GetCSRFToken", "SetAvatar", "BlockUser",
    "UnblockUser", "UnblockEveryone", "SetServer", "SetRecommendedServer", "SetField", "RemoveField", "SetAlias", "SetDescription",
    "AppendDescription",
];

/// Why a request is refused before it's handled, if it is. Browsers mark the requests a web page makes with `Origin`
/// and/or `Sec-Fetch-Site`, scripts and other programs don't: no web page you visit may reach the API. And a page that
/// points its own name at 127.0.0.1 (DNS rebinding) sends that name as `Host`, so on this PC only local names are
/// accepted (AUDIT.md, M3)
fn refused(origin: Option<&str>, fetch_site: Option<&str>, host: Option<&str>, port: i64, external: bool) -> Option<&'static str> {
    // "none": typed in the address bar by the user, not sent by a page
    if origin.is_some() || fetch_site.map(|s| !s.eq_ignore_ascii_case("none")).unwrap_or(false) {
        return Some("Requests from web pages are not allowed");
    }
    if !external {
        if let Some(host) = host {
            let local = ["localhost", "127.0.0.1", "[::1]"].iter().any(|name| host.eq_ignore_ascii_case(name) || host.eq_ignore_ascii_case(&format!("{name}:{port}")));
            if !local {
                return Some("Unexpected Host, only localhost and 127.0.0.1 are accepted");
            }
        }
    }
    None
}

fn respond(mut request: tiny_http::Request) {
    let app = app();
    let header = |name: &'static str| request.headers().iter().find(|h| h.field.equiv(name)).map(|h| h.value.as_str().to_string());
    let why = refused(
        header("Origin").as_deref(),
        header("Sec-Fetch-Site").as_deref(),
        header("Host").as_deref(),
        app.setting_i64("WebServer", "WebServerPort", 7963),
        app.setting_bool("WebServer", "AllowExternalConnections"),
    );
    if let Some(why) = why {
        let mut response = tiny_http::Response::from_string(why).with_status_code(403);
        if let Ok(h) = tiny_http::Header::from_bytes("ws-error", why.as_bytes()) {
            response.add_header(h);
        }
        let _ = request.respond(response);
        return;
    }

    let local = request.remote_addr().map(|a| a.ip().is_loopback()).unwrap_or(false);
    let url = request.url().to_string();
    let mut body = String::new();
    let _ = request.as_reader().read_to_string(&mut body);

    let reply = handle(&app, &url, local, &body);

    let mut response = tiny_http::Response::from_string(reply.body.clone()).with_status_code(reply.status);
    response.add_header(tiny_http::Header::from_bytes("Content-Type", "text/plain; charset=utf-8").unwrap());
    if reply.status > 299 {
        if let Ok(h) = tiny_http::Header::from_bytes("ws-error", reply.body.replace(['\r', '\n'], " ").as_bytes()) {
            response.add_header(h);
        }
    }
    let _ = request.respond(response);
}

/// The request handling itself, separate from the socket so it can be tested
pub fn handle(app: &App, url: &str, local: bool, body: &str) -> Reply {
    let path = url.split('?').next().unwrap_or("/");
    let v2 = path.starts_with("/v2/");
    let path = if v2 { &path[3..] } else { path };
    let q = query(url);
    let get = |k: &str| q.get(k).cloned().unwrap_or_default();

    let reply = |message: String, success: bool, code: Option<u16>, raw: Option<String>| Reply {
        status: code.unwrap_or(if success { 200 } else { 400 }),
        body: if v2 { serde_json::json!({ "Success": success, "Message": message }).to_string() } else { raw.unwrap_or(message) },
    };

    if !local && !app.setting_bool("WebServer", "AllowExternalConnections") {
        return reply("External connections are not allowed".into(), false, Some(401), Some(String::new()));
    }
    if path == "/favicon.ico" {
        return Reply { status: 200, body: String::new() };
    }
    if path == "/Running" {
        return reply("Roblox Account Manager is running".into(), true, None, Some("true".into()));
    }

    let method = path.trim_start_matches('/');
    let password = get("Password");
    let ws_password = app.setting("WebServer", "Password");
    let password_ok = ws_password.chars().count() >= 6 && password == ws_password;
    let invalid_password = || reply("Invalid Password, make sure your password contains 6 or more characters".into(), false, Some(401), Some("Invalid Password".into()));
    let not_allowed = |name: &str| reply(format!("Method `{name}` not allowed"), false, Some(401), Some("Method not allowed".into()));

    if app.setting_bool("WebServer", "EveryRequestRequiresPassword") && !password_ok {
        return invalid_password();
    }

    if method == "CheckVersion" {
        return reply("1.0.0".into(), true, None, None);
    }

    if PROTECTED.contains(&method) && !password_ok {
        return invalid_password();
    }

    if method == "GetAccounts" {
        if !app.setting_bool("WebServer", "AllowGetAccounts") {
            return not_allowed("GetAccounts");
        }
        let group = get("Group");
        let names: Vec<String> = app.store.lock().unwrap().accounts.iter().filter(|a| group.is_empty() || a.group == group).map(|a| a.username.clone()).collect();
        let joined = names.join(",");
        return reply(joined.clone(), true, None, Some(joined));
    }

    if method == "GetAccountsJson" {
        if !app.setting_bool("WebServer", "AllowGetAccounts") {
            return not_allowed("GetAccountsJson");
        }
        let group = get("Group");
        let cookies = password_ok && get("IncludeCookies") == "true" && app.setting_bool("WebServer", "AllowGetCookie");
        let sessions = app.sessions.lock().unwrap();
        let list: Vec<serde_json::Value> = app
            .store
            .lock()
            .unwrap()
            .accounts
            .iter()
            .filter(|a| group.is_empty() || a.group == group)
            .map(|a| {
                serde_json::json!({
                    "Username": a.username, "UserID": a.user_id, "Alias": a.alias, "Description": a.description, "Group": a.group,
                    "CSRFToken": sessions.get(&a.user_id).map(|s| s.csrf.clone()), "LastUsed": a.last_use.roblox_tick(),
                    "Cookie": if cookies { Some(a.security_token.clone()) } else { None }, "Fields": a.fields,
                })
            })
            .collect();
        return reply(serde_json::to_string(&list).unwrap_or_default(), true, None, None);
    }

    if method == "ImportCookie" {
        let cookie = get("Cookie");
        let added = tauri::async_runtime::block_on(app.add_account(&cookie, "")).is_ok();
        return reply(if added { "Cookie successfully imported".into() } else { "[ImportCookie] An error was encountered importing the cookie".into() }, added, None, Some(added.to_string()));
    }

    let name = get("Account");
    if name.is_empty() {
        return reply("Empty Account".into(), false, None, None);
    }

    let Some(account) = app.account(&name) else {
        return reply("Invalid Account, the account's cookie may have expired and resulted in the account being logged out".into(), false, None, Some("Invalid Account".into()));
    };
    let Ok(csrf) = tauri::async_runtime::block_on(app.csrf(&account)) else {
        return reply("Invalid Account, the account's cookie may have expired and resulted in the account being logged out".into(), false, None, Some("Invalid Account".into()));
    };

    match method {
        "GetCookie" => {
            if !app.setting_bool("WebServer", "AllowGetCookie") {
                return not_allowed("GetCookie");
            }
            return reply(account.security_token.clone(), true, None, None);
        }
        "LaunchAccount" => {
            if !app.setting_bool("WebServer", "AllowLaunchAccount") {
                return not_allowed("LaunchAccount");
            }
            let Ok(place_id) = get("PlaceId").parse::<i64>() else {
                return reply("Invalid PlaceId provided".into(), false, None, Some("Invalid PlaceId".into()));
            };
            let opts = JoinOptions { place_id, job_id: get("JobId"), follow_user: get("FollowUser") == "true", join_vip: get("JoinVIP") == "true", privacy_ok: true, ..app.join_options() };
            spawn_join(account.clone(), opts);
            return reply(format!("Launched {name} to {place_id}"), true, None, None);
        }
        "FollowUser" => {
            if !app.setting_bool("WebServer", "AllowLaunchAccount") {
                return not_allowed("FollowUser");
            }
            let user = get("Username");
            if user.is_empty() {
                return reply("Invalid Username Parameter".into(), false, None, None);
            }
            return match tauri::async_runtime::block_on(app.api.user_id(&user, Some(&account.security_token))) {
                Ok(user_id) => {
                    spawn_join(account.clone(), JoinOptions { place_id: user_id, follow_user: true, ..app.join_options() });
                    reply(format!("Joining {user}'s game on {name}"), true, None, None)
                }
                Err(e) => reply(format!("{e}"), false, None, None),
            };
        }
        "GetCSRFToken" => return reply(csrf, true, None, None),
        "GetAlias" => return reply(account.alias.clone(), true, None, None),
        "GetDescription" => return reply(account.description.clone(), true, None, None),
        "BlockUser" | "UnblockUser" if !get("UserId").is_empty() => {
            let unblock = method == "UnblockUser";
            return match tauri::async_runtime::block_on(async {
                app.pin_ok(&account).await?;
                app.api.block(&account.security_token, &csrf, &get("UserId"), unblock).await
            }) {
                Ok(r) => reply(r.body.clone(), r.ok(), Some(r.status), None),
                Err(e) => reply(format!("{e}"), false, Some(500), None),
            };
        }
        "GetBlockedList" => {
            return match tauri::async_runtime::block_on(async {
                app.pin_ok(&account).await?;
                app.api.blocked_list(&account.security_token).await
            }) {
                Ok(r) => reply(r.body.clone(), r.ok(), Some(r.status), None),
                Err(e) => reply(format!("{e}"), false, Some(500), None),
            };
        }
        "UnblockEveryone" => {
            if tauri::async_runtime::block_on(app.pin_ok(&account)).is_err() {
                return reply("Pin is Locked".into(), false, None, None);
            }
            let list = tauri::async_runtime::block_on(app.api.blocked_list(&account.security_token));
            return match list {
                Ok(r) if r.ok() => {
                    let ids: Vec<String> = r.json().and_then(|v| v["blockedUsers"].as_array().cloned()).unwrap_or_default().iter().filter_map(|u| u["userId"].as_i64().map(|i| i.to_string())).collect();
                    let token = account.security_token.clone();
                    tauri::async_runtime::spawn(async move {
                        let app = crate::app::app();
                        for id in ids {
                            if !app.api.block(&token, &csrf, &id, true).await.map(|r| r.ok()).unwrap_or(false) {
                                tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                                let _ = app.api.block(&token, &csrf, &id, true).await;
                            }
                        }
                    });
                    reply("Unblocking Everyone".into(), true, None, None)
                }
                _ => reply("Failed to unblock everyone".into(), false, None, None),
            };
        }
        "SetServer" if !get("PlaceId").is_empty() && !get("JobId").is_empty() => {
            let place: i64 = get("PlaceId").parse().unwrap_or(0);
            return match tauri::async_runtime::block_on(app.api.join_game_instance(&account.security_token, place, &get("JobId"), false)) {
                Ok(r) if r.status == 200 => reply(if r.body.contains("\"joinScriptUrl\":null") { r.body.clone() } else { "Success".into() }, true, None, None),
                Ok(r) => reply(format!("Failed {}: {}", r.status, r.body), false, None, None),
                Err(e) => reply(format!("{e}"), false, None, None),
            };
        }
        "SetRecommendedServer" => {
            let (current_place, servers) = app.last_servers.lock().unwrap().clone();
            let place: i64 = get("PlaceId").parse().unwrap_or(current_place);
            let mut attempts = 0;
            for id in servers.iter().rev() {
                if attempts > 10 {
                    return reply("Too many failed attempts".into(), false, None, None);
                }
                {
                    let mut tried = app.attempted_joins.lock().unwrap();
                    if tried.contains(id) {
                        continue;
                    }
                    if tried.len() > 100 {
                        tried.clear();
                    }
                    tried.push(id.clone());
                }
                attempts += 1;
                if let Ok(r) = tauri::async_runtime::block_on(app.api.join_game_instance(&account.security_token, place, id, false)) {
                    if r.status == 200 {
                        return reply("Success".into(), true, None, None);
                    }
                }
            }
            return reply("Failed".into(), false, None, None);
        }
        "GetField" if !get("Field").is_empty() => return reply(account.field(&get("Field")).to_string(), true, None, None),
        "SetField" if !get("Field").is_empty() && !get("Value").is_empty() => {
            if !app.setting_bool("WebServer", "AllowAccountEditing") {
                return not_allowed("SetField");
            }
            app.update_account(&account.username, |a| {
                a.fields.insert(get("Field"), get("Value"));
            });
            app.save_accounts(false);
            return reply(format!("Set Field {} to {} for {}", get("Field"), get("Value"), account.username), true, None, None);
        }
        "RemoveField" if !get("Field").is_empty() => {
            if !app.setting_bool("WebServer", "AllowAccountEditing") {
                return not_allowed("RemoveField");
            }
            app.update_account(&account.username, |a| {
                a.fields.shift_remove(&get("Field"));
            });
            app.save_accounts(false);
            return reply(format!("Removed Field {} from {}", get("Field"), account.username), true, None, None);
        }
        "SetAvatar" if serde_json::from_str::<serde_json::Value>(body).is_ok() => {
            if !app.setting_bool("WebServer", "AllowAccountEditing") {
                return not_allowed("SetAvatar");
            }
            let avatar: serde_json::Value = serde_json::from_str(body).unwrap();
            let token = account.security_token.clone();
            tauri::async_runtime::spawn(async move {
                let _ = crate::app::app().api.set_avatar(&token, &csrf, &avatar).await;
            });
            return reply(format!("Attempting to set avatar of {} to {}", account.username, body), true, None, None);
        }
        "SetAlias" | "SetDescription" | "AppendDescription" if !body.is_empty() => {
            if !app.setting_bool("WebServer", "AllowAccountEditing") {
                return if method == "AppendDescription" && !v2 { Reply { status: 400, body: "Method not allowed".into() } } else { reply(format!("Method `{method}` not allowed"), false, None, Some("Method not allowed".into())) };
            }
            app.update_account(&account.username, |a| match method {
                "SetAlias" => {
                    a.set_alias(body);
                }
                "SetDescription" => {
                    a.set_description(body);
                }
                _ => {
                    let d = format!("{}{}", a.description, body);
                    a.set_description(&d);
                }
            });
            app.save_accounts(false);
            let text = match method {
                "SetAlias" => format!("Set Alias of {} to {}", account.username, body),
                "SetDescription" => format!("Set Description of {} to {}", account.username, body),
                _ => format!("Appended Description of {} with {}", account.username, body),
            };
            return reply(text, true, None, None);
        }
        _ => {}
    }

    reply("404 not found".into(), false, Some(404), None)
}

fn spawn_join(account: crate::core::accounts::Account, opts: JoinOptions) {
    tauri::async_runtime::spawn(async move {
        let app = app();
        let tracker = app.ensure_tracker(&account.username);
        let opts = JoinOptions { fps_limit: launcher::fps_limit_of(&account), ..opts };
        let result = launcher::join(&app.api, &account.security_token, &tracker, opts).await;
        if let launcher::JoinResult::Error(e) = result {
            app.toast("error", e);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_query_strings() {
        let q = query("/LaunchAccount?Account=Night%20Falcon&PlaceId=1&JobId=&Password=a+b");
        assert_eq!(q["Account"], "Night Falcon");
        assert_eq!(q["PlaceId"], "1");
        assert_eq!(q["JobId"], "");
        assert_eq!(q["Password"], "a b");
    }

    #[test]
    fn web_pages_are_refused() {
        // scripts and programs: no Origin, no Sec-Fetch-Site
        assert_eq!(refused(None, None, Some("localhost:7963"), 7963, false), None);
        assert_eq!(refused(None, None, Some("127.0.0.1:7963"), 7963, false), None);
        assert_eq!(refused(None, None, None, 7963, false), None);
        // the user typing the address in a browser
        assert_eq!(refused(None, Some("none"), Some("127.0.0.1:7963"), 7963, false), None);
        // a page fetching, posting or loading an image from the API
        assert!(refused(Some("https://evil.example"), Some("cross-site"), Some("127.0.0.1:7963"), 7963, false).is_some());
        assert!(refused(None, Some("cross-site"), Some("127.0.0.1:7963"), 7963, false).is_some());
        assert!(refused(Some("null"), None, Some("127.0.0.1:7963"), 7963, true).is_some());
    }

    #[test]
    fn rebound_names_are_refused() {
        assert!(refused(None, None, Some("evil.example:7963"), 7963, false).is_some());
        assert!(refused(None, None, Some("127.0.0.1:8000"), 7963, false).is_some());
        // other devices are allowed in: they use this PC's address or name
        assert_eq!(refused(None, None, Some("192.168.1.20:7963"), 7963, true), None);
    }

    #[test]
    fn every_changing_method_needs_the_password() {
        for method in ["ImportCookie", "SetAvatar", "BlockUser", "UnblockEveryone", "SetServer", "SetField", "SetAlias", "GetCSRFToken", "GetCookie"] {
            assert!(PROTECTED.contains(&method), "{method}");
        }
        for method in ["GetAlias", "GetDescription", "GetField", "GetBlockedList", "GetAccountsJson"] {
            assert!(!PROTECTED.contains(&method), "{method}");
        }
    }
}
