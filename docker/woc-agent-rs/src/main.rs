use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const MAX_TEXT_LEN: usize = 5000;
const MAX_POLL_LIMIT: usize = 500;

#[derive(Clone)]
struct AppState {
    state_dir: PathBuf,
    key_file: PathBuf,
    spool_file: PathBuf,
    wx_cli: Option<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyFile {
    version: u8,
    wxid: String,
    key: String,
    #[serde(rename = "source")]
    source: Option<String>,
    #[serde(rename = "keysFile")]
    keys_file: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: i64,
    #[serde(rename = "updatedAt")]
    updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Cursor {
    v: u8,
    pos: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct AgentMessage {
    id: String,
    time: i64,
    from: String,
    to: String,
    #[serde(rename = "roomId")]
    room_id: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    text: String,
    #[serde(rename = "isSelf")]
    is_self: bool,
    source: Option<String>,
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

#[derive(Debug)]
struct AgentError {
    status: u16,
    message: String,
}

impl AgentError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: 400,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: 409,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: 500,
            message: message.into(),
        }
    }
}

impl AppState {
    fn from_env() -> Self {
        let state_dir = PathBuf::from(
            env::var("WOC_AGENT_STATE_DIR").unwrap_or_else(|_| "/config/.woc-agent".to_string()),
        );
        Self {
            key_file: state_dir.join("wechat.key"),
            spool_file: state_dir.join("messages.ndjson"),
            wx_cli: find_wx_cli(),
            state_dir,
        }
    }

    fn ensure_state_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.state_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.state_dir, fs::Permissions::from_mode(0o700));
        }
        Ok(())
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn read_json_body<T: for<'de> Deserialize<'de>>(body: &[u8]) -> std::result::Result<T, AgentError> {
    if body.is_empty() {
        serde_json::from_slice(b"{}").map_err(|e| AgentError::bad_request(e.to_string()))
    } else {
        serde_json::from_slice(body).map_err(|_| AgentError::bad_request("请求体不是合法 JSON"))
    }
}

fn encode_cursor(pos: usize) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Cursor { v: 1, pos }).unwrap())
}

fn decode_cursor(raw: Option<&str>) -> std::result::Result<usize, AgentError> {
    let Some(raw) = raw.filter(|s| !s.is_empty()) else {
        return Ok(0);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| AgentError::bad_request("cursor 不合法"))?;
    let cursor: Cursor =
        serde_json::from_slice(&bytes).map_err(|_| AgentError::bad_request("cursor 不合法"))?;
    if cursor.v != 1 {
        return Err(AgentError::bad_request("cursor 不合法"));
    }
    Ok(cursor.pos)
}

fn read_key(state: &AppState) -> Result<KeyFile> {
    let data = fs::read_to_string(&state.key_file)?;
    let key: KeyFile = serde_json::from_str(&data)?;
    if key.key.is_empty() {
        return Err(anyhow!("Message Key 文件无效"));
    }
    Ok(key)
}

fn write_key(state: &AppState, key: String, wxid: Option<String>) -> Result<KeyFile> {
    state.ensure_state_dir()?;
    let previous = read_key(state).ok();
    let doc = KeyFile {
        version: 1,
        wxid: wxid
            .or_else(|| previous.as_ref().map(|p| p.wxid.clone()))
            .unwrap_or_default(),
        key,
        source: previous.as_ref().and_then(|p| p.source.clone()),
        keys_file: previous.as_ref().and_then(|p| p.keys_file.clone()),
        created_at: previous.as_ref().map(|p| p.created_at).unwrap_or_else(now),
        updated_at: now(),
    };
    let tmp = state.key_file.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(&doc)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp, &state.key_file)?;
    Ok(doc)
}

fn write_wx_cli_key(state: &AppState, keys_file: PathBuf, wxid: Option<String>) -> Result<KeyFile> {
    validate_wx_cli_keys_file(&keys_file)?;
    state.ensure_state_dir()?;
    let previous = read_key(state).ok();
    let doc = KeyFile {
        version: 1,
        wxid: wxid
            .or_else(|| previous.as_ref().map(|p| p.wxid.clone()))
            .unwrap_or_default(),
        key: "wx-cli".to_string(),
        source: Some("wx-cli".to_string()),
        keys_file: Some(keys_file.to_string_lossy().to_string()),
        created_at: previous.as_ref().map(|p| p.created_at).unwrap_or_else(now),
        updated_at: now(),
    };
    let tmp = state.key_file.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(&doc)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp, &state.key_file)?;
    Ok(doc)
}

fn validate_wx_cli_keys_file(keys_file: &PathBuf) -> Result<()> {
    let raw = fs::read_to_string(keys_file)
        .with_context(|| format!("读取 wx-cli keys 文件失败: {}", keys_file.display()))?;
    let value: Value = serde_json::from_str(&raw)
        .with_context(|| format!("解析 wx-cli keys 文件失败: {}", keys_file.display()))?;
    let keys = value
        .as_object()
        .ok_or_else(|| anyhow!("wx-cli keys 文件不是 JSON object"))?;
    let has_key = keys.values().any(|v| match v {
        Value::String(s) => !s.trim().is_empty(),
        Value::Object(obj) => obj.values().any(|inner| match inner {
            Value::String(s) => !s.trim().is_empty(),
            _ => !inner.is_null(),
        }),
        _ => !v.is_null(),
    });
    if !has_key {
        return Err(anyhow!("wx-cli 未从内存提取到有效 Message Key"));
    }
    Ok(())
}

fn find_wx_cli() -> Option<PathBuf> {
    let bundled = PathBuf::from("/woc/wx");
    if bundled.exists() {
        return Some(bundled);
    }
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .map(|p| p.join("wx"))
            .find(|p| p.exists())
    })
}

fn wx_home() -> PathBuf {
    PathBuf::from(env::var("WOC_WX_CLI_HOME").unwrap_or_else(|_| "/config".to_string()))
}

fn wx_cli_keys_file() -> PathBuf {
    wx_home().join(".wx-cli").join("all_keys.json")
}

fn wx_cli_config_file() -> PathBuf {
    wx_home().join(".wx-cli").join("config.json")
}

fn latest_db_mtime(dir: &PathBuf) -> Option<SystemTime> {
    let mut latest = None;
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let mtime = if path.is_dir() {
            latest_db_mtime(&path).unwrap_or(UNIX_EPOCH)
        } else if path.extension().and_then(|s| s.to_str()) == Some("db") {
            entry
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(UNIX_EPOCH)
        } else {
            continue;
        };
        latest = Some(latest.map_or(mtime, |cur| if mtime > cur { mtime } else { cur }));
    }
    latest
}

fn detect_woc_db_storage() -> Option<PathBuf> {
    let base = wx_home().join("xwechat_files");
    let mut candidates = Vec::new();
    if let Ok(entries) = fs::read_dir(base) {
        for entry in entries.flatten() {
            let storage = entry.path().join("db_storage");
            if storage.is_dir() {
                candidates.push(storage);
            }
        }
    }
    candidates.sort_by_key(|p| latest_db_mtime(p).unwrap_or(UNIX_EPOCH));
    candidates.into_iter().next_back()
}

fn ensure_wx_cli_config() -> Result<()> {
    ensure_wx_cli_layout()?;
    let config = wx_cli_config_file();
    if config.exists() {
        return Ok(());
    }
    let db_dir =
        detect_woc_db_storage().ok_or_else(|| anyhow!("未找到 WOC 微信 db_storage 目录"))?;
    let cli_dir = wx_home().join(".wx-cli");
    fs::create_dir_all(&cli_dir)?;
    let doc = json!({
        "db_dir": db_dir,
        "keys_file": wx_cli_keys_file(),
        "decrypted_dir": cli_dir.join("decrypted"),
        "wechat_process": "wechat"
    });
    fs::write(&config, serde_json::to_vec_pretty(&doc)?)?;
    Ok(())
}

fn ensure_wx_cli_layout() -> Result<()> {
    let source = wx_home().join("xwechat_files");
    if !source.exists() {
        return Ok(());
    }
    let documents = wx_home().join("Documents");
    let compat = documents.join("xwechat_files");
    if compat.exists() {
        return Ok(());
    }
    fs::create_dir_all(&documents)?;
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&source, &compat)
            .with_context(|| format!("创建 wx-cli 兼容路径失败: {}", compat.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = source;
    }
    Ok(())
}

fn run_wx_cli(wx: &PathBuf, args: &[&str]) -> Result<Value> {
    ensure_wx_cli_config()?;
    let output = Command::new(wx)
        .args(args)
        .env("HOME", wx_home())
        .env("WX_HOME", wx_home())
        .output()
        .with_context(|| format!("执行 wx-cli 失败: {}", wx.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "{}",
            if stderr.trim().is_empty() {
                stdout.trim()
            } else {
                stderr.trim()
            }
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        Ok(json!({}))
    } else {
        serde_json::from_str(stdout.trim()).or_else(|_| Ok(json!({ "raw": stdout.trim() })))
    }
}

fn init_with_wx_cli(
    state: &AppState,
    wx: &PathBuf,
    wxid: Option<String>,
) -> std::result::Result<KeyFile, AgentError> {
    run_wx_cli(wx, &["init", "--force"])
        .map_err(|e| AgentError::internal(format!("wx-cli init 失败：{e}")))?;
    let keys_file = wx_cli_keys_file();
    if !keys_file.exists() {
        return Err(AgentError::internal(format!(
            "wx-cli init 未生成 keys 文件：{}",
            keys_file.display()
        )));
    }
    write_wx_cli_key(state, keys_file, wxid).map_err(|e| AgentError::internal(e.to_string()))
}

fn poll_with_wx_cli(wx: &PathBuf, limit: usize) -> std::result::Result<Value, AgentError> {
    let limit_s = limit.to_string();
    let raw = run_wx_cli(wx, &["new-messages", "--json", "-n", &limit_s])
        .or_else(|_| run_wx_cli(wx, &["new-messages", "--json", "--limit", &limit_s]))
        .or_else(|_| run_wx_cli(wx, &["new-messages", "--json"]))
        .map_err(|e| AgentError::internal(format!("wx-cli new-messages 失败：{e}")))?;
    let messages = raw
        .get("messages")
        .cloned()
        .or_else(|| raw.get("data").cloned())
        .or_else(|| {
            if raw.is_array() {
                Some(raw.clone())
            } else {
                None
            }
        })
        .unwrap_or_else(|| json!([]));
    Ok(json!({
        "cursor": encode_cursor(now() as usize),
        "messages": messages,
        "meta": {
            "source": "wx-cli",
            "raw": raw
        }
    }))
}

fn extract_key_from_memory() -> Result<String> {
    if let Ok(key) = env::var("WOC_AGENT_INIT_KEY") {
        let key = key.trim().to_string();
        if !key.is_empty() {
            return Ok(key);
        }
    }
    let helper = PathBuf::from("/woc/woc-key");
    if helper.exists() {
        let out = Command::new(helper)
            .output()
            .context("执行 Message Key 提取器失败")?;
        if out.status.success() {
            let key = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !key.is_empty() {
                return Ok(key);
            }
        }
    }
    let pgrep = Command::new("pgrep").args(["-f", "wechat|WeChat"]).output();
    if pgrep.map(|o| !o.stdout.is_empty()).unwrap_or(false) {
        return Err(anyhow!("当前镜像尚未提供 Message Key 内存提取器"));
    }
    Err(anyhow!("未找到微信进程，无法从内存初始化 Message Key"))
}

fn current_cursor(state: &AppState) -> String {
    let count = read_spool_lines(state)
        .map(|lines| lines.len())
        .unwrap_or(0);
    encode_cursor(count)
}

fn read_spool_lines(state: &AppState) -> Result<Vec<AgentMessage>> {
    if !state.spool_file.exists() {
        return Ok(Vec::new());
    }
    let file = fs::File::open(&state.spool_file)?;
    let mut out = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(message) = serde_json::from_str::<AgentMessage>(&line) {
            out.push(message);
        }
    }
    Ok(out)
}

fn poll_messages(
    state: &AppState,
    cursor: Option<&str>,
    limit: usize,
) -> std::result::Result<Value, AgentError> {
    if !state.key_file.exists() {
        return Err(AgentError::conflict("KEY_REQUIRED"));
    }
    if let Some(wx) = &state.wx_cli {
        let key = read_key(state).map_err(|e| AgentError::internal(e.to_string()))?;
        if key.source.as_deref() == Some("wx-cli") {
            return poll_with_wx_cli(wx, limit);
        }
    }
    let pos = decode_cursor(cursor)?;
    let messages = read_spool_lines(state).map_err(|e| AgentError::internal(e.to_string()))?;
    let next_pos = messages.len().min(pos.saturating_add(limit));
    let slice = if pos >= messages.len() {
        &[]
    } else {
        &messages[pos..next_pos]
    };
    Ok(json!({ "cursor": encode_cursor(next_pos), "messages": slice }))
}

fn append_spool_message(state: &AppState, message: &AgentMessage) -> Result<()> {
    state.ensure_state_dir()?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&state.spool_file)?;
    serde_json::to_writer(&mut file, message)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn shell_quote_single(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn send_text(state: &AppState, to: String, text: String) -> std::result::Result<Value, AgentError> {
    if to.trim().is_empty() || to.len() > 200 {
        return Err(AgentError::bad_request("收件人为空或过长"));
    }
    if text.is_empty() || text.len() > MAX_TEXT_LEN {
        return Err(AgentError::bad_request("文字为空或过长"));
    }
    let client_msg_id = Uuid::new_v4().simple().to_string();
    let message = AgentMessage {
        id: client_msg_id.clone(),
        time: now(),
        from: "self".to_string(),
        to: to.clone(),
        room_id: None,
        kind: "text".to_string(),
        text: text.clone(),
        is_self: true,
        source: Some("send".to_string()),
    };

    if env::var("WOC_AGENT_SEND_MODE").ok().as_deref() == Some("spool") {
        append_spool_message(state, &message).map_err(|e| AgentError::internal(e.to_string()))?;
        return Ok(json!({ "ok": true, "clientMsgId": client_msg_id, "accepted": true }));
    }

    let b64_to = STANDARD.encode(to.as_bytes());
    let b64_text = STANDARD.encode(text.as_bytes());
    let script = [
        "set -e".to_string(),
        "display=\"${DISPLAY:-}\"".to_string(),
        "if [ -z \"$display\" ]; then for x in /tmp/.X11-unix/X*; do [ -e \"$x\" ] || continue; display=\":${x##*X}\"; break; done; fi".to_string(),
        "export DISPLAY=\"${display:-:1}\"".to_string(),
        "command -v xclip >/dev/null 2>&1 || { echo \"xclip not installed\" >&2; exit 127; }".to_string(),
        "command -v xdotool >/dev/null 2>&1 || { echo \"xdotool not installed\" >&2; exit 127; }".to_string(),
        "win=\"$(xdotool search --onlyvisible --name \"微信\\|WeChat\" 2>/dev/null | head -n1 || true)\"".to_string(),
        "[ -n \"$win\" ] || { echo \"未找到可见微信窗口\" >&2; exit 2; }".to_string(),
        "xdotool windowactivate \"$win\"".to_string(),
        "sleep 0.2".to_string(),
        "xdotool key --clearmodifiers ctrl+f".to_string(),
        format!("echo {} | base64 -d | xclip -selection clipboard -i", shell_quote_single(&b64_to)),
        "xdotool key --clearmodifiers ctrl+v".to_string(),
        "sleep 0.2".to_string(),
        "xdotool key --clearmodifiers Return".to_string(),
        "sleep 0.2".to_string(),
        format!("echo {} | base64 -d | xclip -selection clipboard -i", shell_quote_single(&b64_text)),
        "xdotool key --clearmodifiers ctrl+v".to_string(),
        "xdotool key --clearmodifiers Return".to_string(),
    ].join("; ");
    let output = Command::new("bash")
        .args(["-lc", &script])
        .output()
        .map_err(|e| AgentError::internal(e.to_string()))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        let out = String::from_utf8_lossy(&output.stdout);
        return Err(AgentError::internal(format!(
            "发送失败：{}",
            if err.trim().is_empty() {
                out.trim()
            } else {
                err.trim()
            }
        )));
    }
    append_spool_message(state, &message).map_err(|e| AgentError::internal(e.to_string()))?;
    Ok(json!({ "ok": true, "clientMsgId": client_msg_id, "accepted": true }))
}

fn handle(state: &AppState, req: HttpRequest) -> std::result::Result<Value, AgentError> {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/agent/health") => Ok(
            json!({ "ok": true, "hasKey": state.key_file.exists(), "cursor": current_cursor(state) }),
        ),
        ("POST", "/agent/init") => {
            let body: Value = read_json_body(&req.body)?;
            let wxid = body.get("wxid").and_then(Value::as_str).map(str::to_string);
            let (key, source) = match read_key(state) {
                Ok(key) => (key, "file"),
                Err(_) => {
                    if let Ok(key) = env::var("WOC_AGENT_INIT_KEY") {
                        (
                            write_key(state, key, wxid)
                                .map_err(|e| AgentError::internal(e.to_string()))?,
                            "memory",
                        )
                    } else if let Some(wx) = &state.wx_cli {
                        (init_with_wx_cli(state, wx, wxid)?, "memory")
                    } else {
                        (
                            write_key(
                                state,
                                extract_key_from_memory()
                                    .map_err(|e| AgentError::internal(e.to_string()))?,
                                wxid,
                            )
                            .map_err(|e| AgentError::internal(e.to_string()))?,
                            "memory",
                        )
                    }
                }
            };
            Ok(json!({
                "ok": true,
                "keySource": source,
                "account": { "wxid": key.wxid },
                "cursor": current_cursor(state),
                "capabilities": { "poll": true, "sendText": true }
            }))
        }
        ("POST", "/agent/poll") => {
            let body: Value = read_json_body(&req.body)?;
            let limit = body.get("limit").and_then(Value::as_u64).unwrap_or(100) as usize;
            let limit = limit.clamp(1, MAX_POLL_LIMIT);
            poll_messages(state, body.get("cursor").and_then(Value::as_str), limit)
        }
        ("POST", "/agent/send") => {
            let body: Value = read_json_body(&req.body)?;
            if body.get("type").and_then(Value::as_str) != Some("text") {
                return Err(AgentError::bad_request("当前仅支持 text 消息"));
            }
            let to = body
                .get("to")
                .and_then(Value::as_str)
                .ok_or_else(|| AgentError::bad_request("to 必须是字符串"))?
                .to_string();
            let text = body
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| AgentError::bad_request("text 必须是字符串"))?
                .to_string();
            send_text(state, to, text)
        }
        _ => Err(AgentError {
            status: 404,
            message: "not found".to_string(),
        }),
    }
}

fn parse_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let raw_path = parts.next().unwrap_or_default();
    let path = raw_path.split('?').next().unwrap_or(raw_path).to_string();
    let mut content_len = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_len = value.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0; content_len];
    if content_len > 0 {
        reader.read_exact(&mut body)?;
    }
    Ok(HttpRequest { method, path, body })
}

fn write_response(stream: &mut TcpStream, status: u16, body: Value) -> Result<()> {
    let data = serde_json::to_vec(&body)?;
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {} {}\r\ncontent-type: application/json; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        status,
        reason,
        data.len()
    )?;
    stream.write_all(&data)?;
    Ok(())
}

fn serve_connection(state: AppState, mut stream: TcpStream) -> Result<()> {
    let response = match parse_request(&mut stream) {
        Ok(req) => match handle(&state, req) {
            Ok(body) => (200, body),
            Err(e) => (e.status, json!({ "error": e.message })),
        },
        Err(e) => (400, json!({ "error": e.to_string() })),
    };
    write_response(&mut stream, response.0, response.1)
}

fn main() -> Result<()> {
    let host = env::var("WOC_AGENT_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("WOC_AGENT_PORT").unwrap_or_else(|_| "8756".to_string());
    let state = AppState::from_env();
    state.ensure_state_dir()?;
    let listener = TcpListener::bind(format!("{host}:{port}"))?;
    eprintln!("[woc-agent] listening on http://{host}:{port}");
    for stream in listener.incoming() {
        let state = state.clone();
        match stream {
            Ok(stream) => {
                std::thread::spawn(move || {
                    if let Err(e) = serve_connection(state, stream) {
                        eprintln!("[woc-agent] request failed: {e:#}");
                    }
                });
            }
            Err(e) => eprintln!("[woc-agent] accept failed: {e}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trips_position() {
        let encoded = encode_cursor(42);
        assert_eq!(decode_cursor(Some(&encoded)).unwrap(), 42);
        assert_eq!(decode_cursor(None).unwrap(), 0);
    }

    #[test]
    fn invalid_cursor_is_rejected() {
        assert!(decode_cursor(Some("not-a-cursor")).is_err());
    }

    #[test]
    fn key_file_round_trips_and_uses_secure_permissions() {
        let dir = env::temp_dir().join(format!("woc-agent-test-{}", Uuid::new_v4().simple()));
        let state = AppState {
            key_file: dir.join("wechat.key"),
            spool_file: dir.join("messages.ndjson"),
            state_dir: dir.clone(),
            wx_cli: None,
        };
        let key = write_key(
            &state,
            "test-key".to_string(),
            Some("wxid_test".to_string()),
        )
        .unwrap();
        assert_eq!(key.key, "test-key");
        assert_eq!(read_key(&state).unwrap().wxid, "wxid_test");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&state.key_file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn empty_wx_cli_keys_file_is_rejected() {
        let dir = env::temp_dir().join(format!("woc-agent-test-{}", Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();
        let keys_file = dir.join("all_keys.json");
        fs::write(&keys_file, "{}").unwrap();

        let err = validate_wx_cli_keys_file(&keys_file).unwrap_err();
        assert!(err.to_string().contains("Message Key"));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn non_empty_wx_cli_keys_file_is_accepted() {
        let dir = env::temp_dir().join(format!("woc-agent-test-{}", Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();
        let keys_file = dir.join("all_keys.json");
        fs::write(&keys_file, r#"{"message_0.db":"0123456789abcdef"}"#).unwrap();

        validate_wx_cli_keys_file(&keys_file).unwrap();

        fs::remove_dir_all(dir).unwrap();
    }
}
