mod wechat_db;

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
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
const MAX_IMAGE_BYTES: u64 = 10 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Clone)]
struct AppState {
    state_dir: PathBuf,
    key_file: PathBuf,
    spool_file: PathBuf,
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
    #[serde(rename = "dbDir", skip_serializing_if = "Option::is_none")]
    db_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    keys: Option<HashMap<String, String>>,
    #[serde(rename = "createdAt")]
    created_at: i64,
    #[serde(rename = "updatedAt")]
    updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct SpoolCursor {
    v: u8,
    pos: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct DbCursor {
    v: u8,
    source: String,
    sessions: HashMap<String, i64>,
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
    query: HashMap<String, String>,
    body: Vec<u8>,
}

enum AgentResponse {
    Json(Value),
    Binary {
        status: u16,
        content_type: String,
        filename: String,
        body: Vec<u8>,
    },
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

fn encode_spool_cursor(pos: usize) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&SpoolCursor { v: 1, pos }).unwrap())
}

fn decode_spool_cursor(raw: Option<&str>) -> std::result::Result<usize, AgentError> {
    let Some(raw) = raw.filter(|s| !s.is_empty()) else {
        return Ok(0);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| AgentError::bad_request("cursor 不合法"))?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| AgentError::bad_request("cursor 不合法"))?;
    if value.get("v").and_then(Value::as_u64) == Some(2) {
        return Ok(0);
    }
    let cursor: SpoolCursor =
        serde_json::from_value(value).map_err(|_| AgentError::bad_request("cursor 不合法"))?;
    if cursor.v != 1 {
        return Err(AgentError::bad_request("cursor 不合法"));
    }
    Ok(cursor.pos)
}

fn encode_db_cursor(sessions: &HashMap<String, i64>) -> String {
    URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&DbCursor {
            v: 2,
            source: "db".to_string(),
            sessions: sessions.clone(),
        })
        .unwrap(),
    )
}

fn decode_db_cursor(
    raw: Option<&str>,
) -> std::result::Result<Option<HashMap<String, i64>>, AgentError> {
    let Some(raw) = raw.filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| AgentError::bad_request("cursor 不合法"))?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| AgentError::bad_request("cursor 不合法"))?;
    match value.get("v").and_then(Value::as_u64) {
        Some(2) => {
            let cursor: DbCursor = serde_json::from_value(value)
                .map_err(|_| AgentError::bad_request("cursor 不合法"))?;
            Ok(Some(cursor.sessions))
        }
        Some(1) => Ok(None),
        _ => Err(AgentError::bad_request("cursor 不合法")),
    }
}

fn read_key(state: &AppState) -> Result<KeyFile> {
    let data = fs::read_to_string(&state.key_file)?;
    let key: KeyFile = serde_json::from_str(&data)?;
    let has_key_map = key
        .keys
        .as_ref()
        .map(|keys| !keys.is_empty())
        .unwrap_or(false);
    let has_keys_file = key
        .keys_file
        .as_ref()
        .map(|path| !path.trim().is_empty())
        .unwrap_or(false);
    if key.key.is_empty() && !has_key_map && !has_keys_file {
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
        source: Some("env".to_string()),
        keys_file: None,
        db_dir: None,
        keys: None,
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

fn write_wechat_db_key(
    state: &AppState,
    init: wechat_db::InitData,
    wxid: Option<String>,
) -> Result<KeyFile> {
    state.ensure_state_dir()?;
    let previous = read_key(state).ok();
    let doc = KeyFile {
        version: 1,
        wxid: wxid
            .or_else(|| previous.as_ref().map(|p| p.wxid.clone()))
            .unwrap_or_default(),
        key: "woc-agent".to_string(),
        source: Some("woc-agent".to_string()),
        keys_file: None,
        db_dir: Some(init.db_dir.to_string_lossy().into_owned()),
        keys: Some(init.keys),
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

fn current_cursor(state: &AppState) -> String {
    if let Ok(key) = read_key(state) {
        if let Ok(Some((db_dir, keys))) = key_db_material(&key) {
            if let Ok(session_state) =
                wechat_db::current_session_state(db_dir, keys, state.state_dir.join("cache"))
            {
                return encode_db_cursor(&session_state);
            }
            return encode_db_cursor(&HashMap::new());
        }
    }
    let count = read_spool_lines(state)
        .map(|lines| lines.len())
        .unwrap_or(0);
    encode_spool_cursor(count)
}

fn key_db_material(key: &KeyFile) -> Result<Option<(PathBuf, HashMap<String, String>)>> {
    if let (Some(db_dir), Some(keys)) = (&key.db_dir, &key.keys) {
        if !keys.is_empty() {
            return Ok(Some((PathBuf::from(db_dir), keys.clone())));
        }
    }
    if let Some(keys_file) = key
        .keys_file
        .as_ref()
        .filter(|path| !path.trim().is_empty())
    {
        let keys = wechat_db::read_keys_file(&PathBuf::from(keys_file))?;
        let db_dir = key
            .db_dir
            .as_ref()
            .map(PathBuf::from)
            .or_else(wechat_db::detect_db_storage)
            .ok_or_else(|| anyhow!("未找到 WOC 微信 db_storage 目录"))?;
        return Ok(Some((db_dir, keys)));
    }
    Ok(None)
}

fn init_from_memory(
    state: &AppState,
    wxid: Option<String>,
) -> std::result::Result<KeyFile, AgentError> {
    let init = wechat_db::init_from_memory()
        .map_err(|e| AgentError::internal(format!("Message Key 初始化失败：{e}")))?;
    write_wechat_db_key(state, init, wxid).map_err(|e| AgentError::internal(e.to_string()))
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
    let key = read_key(state).map_err(|e| AgentError::internal(e.to_string()))?;
    if let Some((db_dir, keys)) =
        key_db_material(&key).map_err(|e| AgentError::internal(e.to_string()))?
    {
        let cursor_state = decode_db_cursor(cursor)?;
        let data = wechat_db::poll_new_messages(
            db_dir,
            keys,
            cursor_state,
            limit,
            state.state_dir.join("cache"),
        )
        .map_err(|e| AgentError::internal(format!("读取新消息失败：{e}")))?;
        let wechat_db::PollData {
            messages,
            new_state,
            meta,
        } = data;
        let cursor = encode_db_cursor(&new_state);
        return Ok(json!({
            "cursor": cursor,
            "messages": messages,
            "meta": {
                "source": "woc-agent",
                "newState": new_state,
                "raw": meta
            }
        }));
    }
    let pos = decode_spool_cursor(cursor)?;
    let messages = read_spool_lines(state).map_err(|e| AgentError::internal(e.to_string()))?;
    let next_pos = messages.len().min(pos.saturating_add(limit));
    let slice = if pos >= messages.len() {
        &[]
    } else {
        &messages[pos..next_pos]
    };
    Ok(json!({ "cursor": encode_spool_cursor(next_pos), "messages": slice }))
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

fn safe_media_file_stem(raw: &str) -> String {
    let stem: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(120)
        .collect();
    if stem.is_empty() {
        "image".to_string()
    } else {
        stem
    }
}

fn safe_media_file_name(raw: &str, fallback: &str) -> String {
    let name = raw
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(raw)
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(180)
        .collect::<String>()
        .trim_matches('.')
        .to_string();
    if name.is_empty() {
        fallback.to_string()
    } else {
        name
    }
}

fn image_mime_parts(
    mime_type: &str,
) -> std::result::Result<(&'static str, &'static str), AgentError> {
    match mime_type.trim().to_ascii_lowercase().as_str() {
        "image/png" => Ok(("image/png", "png")),
        "image/jpeg" | "image/jpg" => Ok(("image/jpeg", "jpg")),
        "image/webp" => Ok(("image/webp", "webp")),
        _ => Err(AgentError::bad_request(
            "mimeType 仅支持 image/png、image/jpeg、image/webp",
        )),
    }
}

#[derive(Debug, Clone)]
struct SendTarget {
    id: String,
    query: String,
    is_group: bool,
    search_uses_remark: bool,
}

fn resolve_send_target(state: &AppState, to: &str) -> std::result::Result<SendTarget, AgentError> {
    if let Ok(key) = read_key(state) {
        if let Ok(Some((db_dir, keys))) = key_db_material(&key) {
            match wechat_db::resolve_recipient_by_username(
                db_dir,
                keys,
                state.state_dir.join("cache"),
                to,
            ) {
                Ok(Some(recipient)) => {
                    return Ok(SendTarget {
                        id: recipient.username,
                        query: recipient.display,
                        is_group: recipient.is_group,
                        search_uses_remark: recipient.search_uses_remark,
                    });
                }
                Ok(None) => {
                    return Err(AgentError::bad_request(
                        "未找到收件人：to 必须是 poll 返回的内部 id",
                    ));
                }
                Err(e) => {
                    return Err(AgentError::bad_request(format!("收件人解析失败：{e}")));
                }
            }
        }
    }
    Err(AgentError::bad_request(
        "无法解析收件人，请先完成 /api/init",
    ))
}

fn send_text(state: &AppState, to: String, text: String) -> std::result::Result<Value, AgentError> {
    let to = to.trim().to_string();
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

    let target = resolve_send_target(state, &to)?;
    if target.is_group && !target.search_uses_remark {
        return Err(AgentError::bad_request(
            "群聊发送必须先设置唯一备注，避免微信搜索误选会话",
        ));
    }
    let b64_to = STANDARD.encode(target.query.as_bytes());
    let b64_text = STANDARD.encode(text.as_bytes());
    let script = [
        "set -e".to_string(),
        "display=\"${DISPLAY:-}\"".to_string(),
        "if [ -z \"$display\" ]; then for x in /tmp/.X11-unix/X*; do [ -e \"$x\" ] || continue; display=\":${x##*X}\"; break; done; fi".to_string(),
        "export DISPLAY=\"${display:-:1}\"".to_string(),
        "command -v xclip >/dev/null 2>&1 || { echo \"xclip not installed\" >&2; exit 127; }".to_string(),
        "command -v xdotool >/dev/null 2>&1 || { echo \"xdotool not installed\" >&2; exit 127; }".to_string(),
        "command -v timeout >/dev/null 2>&1 || { echo \"timeout not installed\" >&2; exit 127; }".to_string(),
        "clip_pid=\"\"".to_string(),
        "cleanup_clip() { if [ -n \"${clip_pid:-}\" ]; then kill \"$clip_pid\" 2>/dev/null || true; wait \"$clip_pid\" 2>/dev/null || true; clip_pid=\"\"; fi; }".to_string(),
        "set_clip() { cleanup_clip; printf '%s' \"$1\" | base64 -d | xclip -selection clipboard -target UTF8_STRING -loops 5 -i >/dev/null 2>&1 & clip_pid=$!; sleep 0.25; }".to_string(),
        "paste_clip() { xdotool key --clearmodifiers ctrl+v; for i in $(seq 1 30); do if ! kill -0 \"$clip_pid\" 2>/dev/null; then wait \"$clip_pid\" 2>/dev/null || true; clip_pid=\"\"; sleep 0.1; return 0; fi; sleep 0.1; done; echo \"微信未读取剪贴板\" >&2; return 3; }".to_string(),
        "trap cleanup_clip EXIT".to_string(),
        "if command -v xprop >/dev/null 2>&1; then for browser_win in $({ xdotool search --name '微信' 2>/dev/null || true; xdotool search --name 'WeChat' 2>/dev/null || true; } | sort -u); do class=\"$(xprop -id \"$browser_win\" WM_CLASS 2>/dev/null || true)\"; case \"$class\" in *wechat*) ;; *) xdotool windowclose \"$browser_win\" 2>/dev/null || true; sleep 0.3;; esac; done; fi".to_string(),
        "win=\"$(xdotool search --onlyvisible --class 'wechat' 2>/dev/null | tail -n1 || true)\"".to_string(),
        "[ -n \"$win\" ] || { active=\"$(xdotool getactivewindow 2>/dev/null || true)\"; active_name=\"\"; if [ -n \"$active\" ]; then active_name=\"$(xdotool getwindowname \"$active\" 2>/dev/null || true)\"; case \"$active_name\" in *微信*|*WeChat*) win=\"$active\";; esac; fi; }".to_string(),
        "[ -n \"$win\" ] || win=\"$(xdotool search --onlyvisible --name '微信' 2>/dev/null | tail -n1 || true)\"".to_string(),
        "[ -n \"$win\" ] || win=\"$(xdotool search --onlyvisible --name 'WeChat' 2>/dev/null | tail -n1 || true)\"".to_string(),
        "[ -n \"$win\" ] || win=\"$(xdotool search --onlyvisible --class 'wechat' 2>/dev/null | tail -n1 || true)\"".to_string(),
        "[ -n \"$win\" ] || { echo \"未找到可见微信窗口\" >&2; exit 2; }".to_string(),
        "xdotool windowactivate \"$win\"".to_string(),
        "sleep 0.2".to_string(),
        "eval \"$(xdotool getwindowgeometry --shell \"$win\")\"".to_string(),
        "root_x=${X:-0}; root_y=${Y:-0}; root_w=${WIDTH:-1856}; root_h=${HEIGHT:-857}".to_string(),
        "input_x=$((root_x + 500)); input_y=$((root_y + root_h - 157)); send_x=$((root_x + root_w - 67)); send_y=$((root_y + root_h - 34))".to_string(),
        "main_win=\"$(xdotool search --onlyvisible --class 'wechat' 2>/dev/null | tail -n1 || true)\"; if [ -n \"$main_win\" ]; then win=\"$main_win\"; xdotool windowactivate \"$win\"; xdotool windowraise \"$win\" 2>/dev/null || true; sleep 0.2; fi; xdotool key --clearmodifiers Escape; sleep 0.1; xdotool mousemove $((root_x + 31)) $((root_y + 96)) click 1; sleep 0.2; xdotool key --clearmodifiers ctrl+f; sleep 0.3".to_string(),
        "xdotool key --clearmodifiers ctrl+a; sleep 0.05; xdotool key --clearmodifiers BackSpace; sleep 0.05; xdotool key --clearmodifiers ctrl+a; sleep 0.05; xdotool key --clearmodifiers Delete; sleep 0.2; ".to_string()
            + &format!("set_clip {}", shell_quote_single(&b64_to))
            + "; paste_clip; sleep 1.8; xdotool key --clearmodifiers Return",
        "sleep 1.5; xdotool key --clearmodifiers Escape; sleep 0.2".to_string(),
        "xdotool mousemove \"$input_x\" \"$input_y\" click 1".to_string(),
        "sleep 0.2".to_string(),
        "xdotool key --clearmodifiers ctrl+a BackSpace".to_string(),
        "sleep 0.2".to_string(),
        format!("set_clip {}", shell_quote_single(&b64_text)),
        "paste_clip".to_string(),
        "sleep 0.2".to_string(),
        "xdotool mousemove \"$send_x\" \"$send_y\" click 1".to_string(),
        "sleep 0.5".to_string(),
    ].join("; ");
    let output = Command::new("timeout")
        .args(["60s", "bash", "-lc", &script])
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
    Ok(json!({
        "ok": true,
        "clientMsgId": client_msg_id,
        "accepted": true,
        "target": {
            "id": target.id,
            "query": target.query,
            "isGroup": target.is_group
        }
    }))
}

fn send_downloaded_file(
    state: &AppState,
    to: String,
    media_url: String,
    file_name: String,
    kind: &'static str,
    text: &'static str,
    max_bytes: u64,
    timeout_secs: &'static str,
    error_prefix: &'static str,
) -> std::result::Result<Value, AgentError> {
    let to = to.trim().to_string();
    let media_url = media_url.trim().to_string();
    if to.trim().is_empty() || to.len() > 200 {
        return Err(AgentError::bad_request("收件人为空或过长"));
    }
    if media_url.is_empty() || media_url.len() > 4096 {
        return Err(AgentError::bad_request("mediaUrl 为空或过长"));
    }
    if !(media_url.starts_with("http://") || media_url.starts_with("https://")) {
        return Err(AgentError::bad_request("mediaUrl 必须是 http/https URL"));
    }
    let client_msg_id = Uuid::new_v4().simple().to_string();
    let message = AgentMessage {
        id: client_msg_id.clone(),
        time: now(),
        from: "self".to_string(),
        to: to.clone(),
        room_id: None,
        kind: kind.to_string(),
        text: text.to_string(),
        is_self: true,
        source: Some("send".to_string()),
    };

    if env::var("WOC_AGENT_SEND_MODE").ok().as_deref() == Some("spool") {
        append_spool_message(state, &message).map_err(|e| AgentError::internal(e.to_string()))?;
        return Ok(json!({ "ok": true, "clientMsgId": client_msg_id, "accepted": true }));
    }

    let target = resolve_send_target(state, &to)?;
    if target.is_group && !target.search_uses_remark {
        return Err(AgentError::bad_request(
            "群聊发送必须先设置唯一备注，避免微信搜索误选会话",
        ));
    }

    let transfer_dir = PathBuf::from("/config/Desktop");
    fs::create_dir_all(&transfer_dir).map_err(|e| AgentError::internal(e.to_string()))?;
    let safe_file_name = safe_media_file_name(&file_name, &client_msg_id);
    let media_file = transfer_dir.join(format!("woc-send-{safe_file_name}"));
    let media_path = media_file.to_string_lossy().to_string();
    let b64_media_path = STANDARD.encode(media_path.as_bytes());
    let b64_to = STANDARD.encode(target.query.as_bytes());
    let script = [
        "set -e".to_string(),
        "display=\"${DISPLAY:-}\"".to_string(),
        "if [ -z \"$display\" ]; then for x in /tmp/.X11-unix/X*; do [ -e \"$x\" ] || continue; display=\":${x##*X}\"; break; done; fi".to_string(),
        "export DISPLAY=\"${display:-:1}\"".to_string(),
        "command -v curl >/dev/null 2>&1 || { echo \"curl not installed\" >&2; exit 127; }".to_string(),
        "command -v xclip >/dev/null 2>&1 || { echo \"xclip not installed\" >&2; exit 127; }".to_string(),
        "command -v xdotool >/dev/null 2>&1 || { echo \"xdotool not installed\" >&2; exit 127; }".to_string(),
        "command -v timeout >/dev/null 2>&1 || { echo \"timeout not installed\" >&2; exit 127; }".to_string(),
        "clip_pid=\"\"".to_string(),
        "cleanup_clip() { if [ -n \"${clip_pid:-}\" ]; then kill \"$clip_pid\" 2>/dev/null || true; wait \"$clip_pid\" 2>/dev/null || true; clip_pid=\"\"; fi; }".to_string(),
        "set_text_clip() { cleanup_clip; printf '%s' \"$1\" | base64 -d | xclip -selection clipboard -target UTF8_STRING -loops 5 -i >/dev/null 2>&1 & clip_pid=$!; sleep 0.25; }".to_string(),
        "paste_clip() { xdotool key --clearmodifiers ctrl+v; for i in $(seq 1 30); do if ! kill -0 \"$clip_pid\" 2>/dev/null; then wait \"$clip_pid\" 2>/dev/null || true; clip_pid=\"\"; sleep 0.1; return 0; fi; sleep 0.1; done; echo \"微信未读取剪贴板\" >&2; return 3; }".to_string(),
        "trap cleanup_clip EXIT".to_string(),
        format!("img={}", shell_quote_single(&media_path)),
        format!("img_b64={}", shell_quote_single(&b64_media_path)),
        "rm -f \"$img\"".to_string(),
        format!(
            "curl -fsSL --connect-timeout 10 --max-time 45 --retry 1 --output \"$img\" {}",
            shell_quote_single(&media_url)
        ),
        format!("size=$(wc -c < \"$img\"); [ \"$size\" -gt 0 ] && [ \"$size\" -le {} ] || {{ echo \"文件大小不合法或超过限制\" >&2; exit 4; }}", max_bytes),
        "chown abc:abc \"$img\" 2>/dev/null || true".to_string(),
        "if command -v xprop >/dev/null 2>&1; then for browser_win in $({ xdotool search --name '微信' 2>/dev/null || true; xdotool search --name 'WeChat' 2>/dev/null || true; } | sort -u); do class=\"$(xprop -id \"$browser_win\" WM_CLASS 2>/dev/null || true)\"; case \"$class\" in *wechat*) ;; *) xdotool windowclose \"$browser_win\" 2>/dev/null || true; sleep 0.3;; esac; done; fi".to_string(),
        "win=\"$(xdotool search --onlyvisible --class 'wechat' 2>/dev/null | tail -n1 || true)\"".to_string(),
        "[ -n \"$win\" ] || { active=\"$(xdotool getactivewindow 2>/dev/null || true)\"; active_name=\"\"; if [ -n \"$active\" ]; then active_name=\"$(xdotool getwindowname \"$active\" 2>/dev/null || true)\"; case \"$active_name\" in *微信*|*WeChat*) win=\"$active\";; esac; fi; }".to_string(),
        "[ -n \"$win\" ] || win=\"$(xdotool search --onlyvisible --name '微信' 2>/dev/null | tail -n1 || true)\"".to_string(),
        "[ -n \"$win\" ] || win=\"$(xdotool search --onlyvisible --name 'WeChat' 2>/dev/null | tail -n1 || true)\"".to_string(),
        "[ -n \"$win\" ] || win=\"$(xdotool search --onlyvisible --class 'wechat' 2>/dev/null | tail -n1 || true)\"".to_string(),
        "[ -n \"$win\" ] || { echo \"未找到可见微信窗口\" >&2; exit 2; }".to_string(),
        "xdotool windowactivate \"$win\"".to_string(),
        "sleep 0.2".to_string(),
        "eval \"$(xdotool getwindowgeometry --shell \"$win\")\"".to_string(),
        "root_x=${X:-0}; root_y=${Y:-0}; root_w=${WIDTH:-1856}; root_h=${HEIGHT:-857}".to_string(),
        "input_x=$((root_x + 500)); input_y=$((root_y + root_h - 157)); file_x=$((root_x + 433)); file_y=$((root_y + root_h - 194)); send_x=$((root_x + root_w - 67)); send_y=$((root_y + root_h - 34))".to_string(),
        "main_win=\"$(xdotool search --onlyvisible --class 'wechat' 2>/dev/null | tail -n1 || true)\"; if [ -n \"$main_win\" ]; then win=\"$main_win\"; xdotool windowactivate \"$win\"; xdotool windowraise \"$win\" 2>/dev/null || true; sleep 0.2; fi; xdotool key --clearmodifiers Escape; sleep 0.1; xdotool mousemove $((root_x + 31)) $((root_y + 96)) click 1; sleep 0.2; xdotool key --clearmodifiers ctrl+f; sleep 0.3".to_string(),
        "xdotool key --clearmodifiers ctrl+a; sleep 0.05; xdotool key --clearmodifiers BackSpace; sleep 0.05; xdotool key --clearmodifiers ctrl+a; sleep 0.05; xdotool key --clearmodifiers Delete; sleep 0.2; ".to_string()
            + &format!("set_text_clip {}", shell_quote_single(&b64_to))
            + "; paste_clip; sleep 1.8; xdotool key --clearmodifiers Return",
        "sleep 1.5; xdotool key --clearmodifiers Escape; sleep 0.2".to_string(),
        "xdotool mousemove \"$input_x\" \"$input_y\" click 1".to_string(),
        "sleep 0.2".to_string(),
        "xdotool key --clearmodifiers ctrl+a BackSpace".to_string(),
        "sleep 0.2".to_string(),
        "xdotool mousemove \"$file_x\" \"$file_y\" click 1".to_string(),
        "sleep 0.8".to_string(),
        "xdotool key --clearmodifiers ctrl+l".to_string(),
        "sleep 0.2".to_string(),
        "printf '%s' \"$img_b64\" | base64 -d | xdotool type --delay 1 --file -".to_string(),
        "sleep 0.2".to_string(),
        "xdotool key --clearmodifiers Return".to_string(),
        "sleep 1.2".to_string(),
        "xdotool mousemove \"$send_x\" \"$send_y\" click 1".to_string(),
        "sleep 0.5".to_string(),
    ].join("; ");
    let output = Command::new("timeout")
        .args([timeout_secs, "bash", "-lc", &script])
        .output()
        .map_err(|e| AgentError::internal(e.to_string()))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        let out = String::from_utf8_lossy(&output.stdout);
        return Err(AgentError::internal(format!(
            "{}：{}",
            error_prefix,
            if err.trim().is_empty() {
                out.trim()
            } else {
                err.trim()
            }
        )));
    }
    append_spool_message(state, &message).map_err(|e| AgentError::internal(e.to_string()))?;
    Ok(json!({
        "ok": true,
        "clientMsgId": client_msg_id,
        "accepted": true,
        "target": {
            "id": target.id,
            "query": target.query,
            "isGroup": target.is_group
        }
    }))
}

fn send_image(
    state: &AppState,
    to: String,
    media_url: String,
    mime_type: String,
    media_id: String,
) -> std::result::Result<Value, AgentError> {
    let (_, ext) = image_mime_parts(&mime_type)?;
    let file_stem = safe_media_file_stem(if media_id.trim().is_empty() {
        "image"
    } else {
        media_id.trim()
    });
    send_downloaded_file(
        state,
        to,
        media_url,
        format!("{file_stem}.{ext}"),
        "image",
        "[图片]",
        MAX_IMAGE_BYTES,
        "80s",
        "发送图片失败",
    )
}

fn send_file(
    state: &AppState,
    to: String,
    media_url: String,
    file_name: String,
) -> std::result::Result<Value, AgentError> {
    send_downloaded_file(
        state,
        to,
        media_url.clone(),
        safe_media_file_name(&file_name, &safe_media_file_name(&media_url, "file")),
        "file",
        "[文件]",
        MAX_FILE_BYTES,
        "140s",
        "发送文件失败",
    )
}

fn handle(state: &AppState, req: HttpRequest) -> std::result::Result<AgentResponse, AgentError> {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/agent/health") => Ok(AgentResponse::Json(
            json!({ "ok": true, "hasKey": state.key_file.exists(), "cursor": current_cursor(state) }),
        )),
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
                    } else {
                        (init_from_memory(state, wxid)?, "memory")
                    }
                }
            };
            Ok(AgentResponse::Json(json!({
                "ok": true,
                "keySource": source,
                "account": { "wxid": key.wxid },
                "cursor": current_cursor(state),
                "capabilities": { "poll": true, "sendText": true, "sendImage": true, "sendFile": true }
            })))
        }
        ("POST", "/agent/poll") => {
            let body: Value = read_json_body(&req.body)?;
            let limit = body.get("limit").and_then(Value::as_u64).unwrap_or(100) as usize;
            let limit = limit.clamp(1, MAX_POLL_LIMIT);
            poll_messages(state, body.get("cursor").and_then(Value::as_str), limit)
                .map(AgentResponse::Json)
        }
        ("POST", "/agent/send") => {
            let body: Value = read_json_body(&req.body)?;
            let message_type = body.get("type").and_then(Value::as_str).unwrap_or("text");
            let to = body
                .get("to")
                .and_then(Value::as_str)
                .ok_or_else(|| AgentError::bad_request("to 必须是字符串"))?
                .to_string();
            match message_type {
                "text" => {
                    let text = body
                        .get("text")
                        .and_then(Value::as_str)
                        .ok_or_else(|| AgentError::bad_request("text 必须是字符串"))?
                        .to_string();
                    send_text(state, to, text).map(AgentResponse::Json)
                }
                "image" => {
                    let media_url = body
                        .get("mediaUrl")
                        .and_then(Value::as_str)
                        .ok_or_else(|| AgentError::bad_request("mediaUrl 必须是字符串"))?
                        .to_string();
                    let mime_type = body
                        .get("mimeType")
                        .and_then(Value::as_str)
                        .unwrap_or("image/png")
                        .to_string();
                    let media_id = body
                        .get("mediaId")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    send_image(state, to, media_url, mime_type, media_id).map(AgentResponse::Json)
                }
                "file" => {
                    let media_url = body
                        .get("mediaUrl")
                        .or_else(|| body.get("fileUrl"))
                        .or_else(|| body.get("url"))
                        .and_then(Value::as_str)
                        .ok_or_else(|| AgentError::bad_request("mediaUrl 必须是字符串"))?
                        .to_string();
                    let file_name = body
                        .get("fileName")
                        .or_else(|| body.get("name"))
                        .or_else(|| body.get("mediaId"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    send_file(state, to, media_url, file_name).map(AgentResponse::Json)
                }
                _ => Err(AgentError::bad_request("当前仅支持 text/image/file 消息")),
            }
        }
        ("GET", "/agent/media") => download_media(state, &req.query),
        _ => Err(AgentError {
            status: 404,
            message: "not found".to_string(),
        }),
    }
}

fn download_media(
    state: &AppState,
    query: &HashMap<String, String>,
) -> std::result::Result<AgentResponse, AgentError> {
    let roomid = query
        .get("roomid")
        .map(String::as_str)
        .unwrap_or_default()
        .trim();
    let msgid = query
        .get("msgid")
        .map(String::as_str)
        .unwrap_or_default()
        .trim();
    if roomid.is_empty() || msgid.is_empty() {
        return Err(AgentError::bad_request("roomid 和 msgid 必须传递"));
    }
    let key = read_key(state).map_err(|e| AgentError::internal(e.to_string()))?;
    let db_dir = key
        .db_dir
        .as_ref()
        .filter(|path| !path.trim().is_empty())
        .map(PathBuf::from)
        .or_else(wechat_db::detect_db_storage)
        .ok_or_else(|| AgentError::internal("未找到 WOC 微信 db_storage 目录"))?;
    let keys = key
        .keys
        .clone()
        .or_else(|| {
            key.keys_file
                .as_ref()
                .and_then(|path| wechat_db::read_keys_file(PathBuf::from(path).as_path()).ok())
        })
        .ok_or_else(|| AgentError::internal("未找到 Message Key"))?;
    let media =
        wechat_db::read_image_media(db_dir, keys, state.state_dir.join("cache"), roomid, msgid)
            .map_err(|e| AgentError::internal(e.to_string()))?
            .ok_or_else(|| AgentError {
                status: 404,
                message: "图片文件不存在或尚未下载到本地".to_string(),
            })?;
    Ok(AgentResponse::Binary {
        status: 200,
        content_type: media.content_type,
        filename: media.filename,
        body: media.data,
    })
}

fn parse_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let raw_path = parts.next().unwrap_or_default();
    let path = raw_path.split('?').next().unwrap_or(raw_path).to_string();
    let query = parse_query(
        raw_path
            .split_once('?')
            .map(|(_, query)| query)
            .unwrap_or_default(),
    );
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
    Ok(HttpRequest {
        method,
        path,
        query,
        body,
    })
}

fn parse_query(raw: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(percent_decode(key), percent_decode(value));
    }
    out
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(value) = u8::from_str_radix(hex, 16) {
                    out.push(value);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
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

fn write_binary_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    filename: &str,
    body: &[u8],
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-disposition: inline; filename=\"{}\"\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        status,
        reason,
        content_type,
        header_safe_filename(filename),
        body.len()
    )?;
    stream.write_all(body)?;
    Ok(())
}

fn header_safe_filename(filename: &str) -> String {
    filename
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
        .collect::<String>()
}

fn serve_connection(state: AppState, mut stream: TcpStream) -> Result<()> {
    let response = match parse_request(&mut stream) {
        Ok(req) => match handle(&state, req) {
            Ok(AgentResponse::Json(body)) => return write_response(&mut stream, 200, body),
            Ok(AgentResponse::Binary {
                status,
                content_type,
                filename,
                body,
            }) => {
                return write_binary_response(&mut stream, status, &content_type, &filename, &body)
            }
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
    fn spool_cursor_round_trips_position() {
        let encoded = encode_spool_cursor(42);
        assert_eq!(decode_spool_cursor(Some(&encoded)).unwrap(), 42);
        assert_eq!(decode_spool_cursor(None).unwrap(), 0);
    }

    #[test]
    fn db_cursor_round_trips_session_state() {
        let sessions = HashMap::from([("wxid_test".to_string(), 123_i64)]);
        let encoded = encode_db_cursor(&sessions);
        assert_eq!(decode_db_cursor(Some(&encoded)).unwrap().unwrap(), sessions);
        assert!(decode_db_cursor(None).unwrap().is_none());
    }

    #[test]
    fn invalid_cursor_is_rejected() {
        assert!(decode_db_cursor(Some("not-a-cursor")).is_err());
    }

    #[test]
    fn db_poll_accepts_legacy_spool_cursor_as_empty_state() {
        let encoded = encode_spool_cursor(42);
        assert!(decode_db_cursor(Some(&encoded)).unwrap().is_none());
    }

    #[test]
    fn key_file_round_trips_and_uses_secure_permissions() {
        let dir = env::temp_dir().join(format!("woc-agent-test-{}", Uuid::new_v4().simple()));
        let state = AppState {
            key_file: dir.join("wechat.key"),
            spool_file: dir.join("messages.ndjson"),
            state_dir: dir.clone(),
        };
        let key = write_key(
            &state,
            "test-key".to_string(),
            Some("wxid_test".to_string()),
        )
        .unwrap();
        assert_eq!(key.key, "test-key");
        assert_eq!(key.source.as_deref(), Some("env"));
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
    fn empty_keys_json_is_rejected() {
        let err = wechat_db::parse_keys_value(&json!({})).unwrap_err();
        assert!(err.to_string().contains("Message Key"));
    }

    #[test]
    fn non_empty_keys_json_is_accepted() {
        let keys = wechat_db::parse_keys_value(&json!({
            "message/message_0.db": { "enc_key": "0123456789abcdef" }
        }))
        .unwrap();
        assert_eq!(
            keys.get("message/message_0.db").map(String::as_str),
            Some("0123456789abcdef")
        );
    }
}
