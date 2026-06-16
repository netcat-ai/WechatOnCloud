// Portions of this module are adapted from jackwener/wx-cli (Apache-2.0).
// The agent keeps this code in-process so message state and HTTP cursors stay owned by WOC.
use aes::Aes256;
use anyhow::{anyhow, bail, Context, Result};
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use cbc::Decryptor;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const HEX_PATTERN_LEN: usize = 96;
const CHUNK_SIZE: usize = 2 * 1024 * 1024;
const PAGE_SZ: usize = 4096;
const SALT_SZ: usize = 16;
const RESERVE_SZ: usize = 80;
const WAL_HDR_SZ: usize = 32;
const WAL_FRAME_HDR: usize = 24;
const SQLITE_HDR: &[u8] = b"SQLite format 3\x00";

type Aes256CbcDec = Decryptor<Aes256>;
type Block = aes::cipher::Block<Aes256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyEntry {
    db_name: String,
    enc_key: String,
    salt: String,
}

#[derive(Debug, Clone)]
pub struct InitData {
    pub db_dir: PathBuf,
    pub keys: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PollData {
    pub messages: Vec<Value>,
    pub new_state: HashMap<String, i64>,
    pub meta: Value,
}

#[derive(Debug, Clone)]
pub struct Recipient {
    pub username: String,
    pub display: String,
    pub is_group: bool,
    pub search_uses_remark: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MtimeEntry {
    db_mt: u64,
    wal_mt: u64,
    path: String,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    db_mtime: u64,
    wal_mtime: u64,
    decrypted_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReferMsg {
    msg_type: String,
    svrid: String,
    fromusr: String,
    chatusr: String,
    displayname: String,
    content: String,
    createtime: String,
}

impl ReferMsg {
    fn base_type(&self) -> i64 {
        self.msg_type.trim().parse::<i64>().unwrap_or(0)
    }

    fn createtime_i64(&self) -> i64 {
        self.createtime.trim().parse::<i64>().unwrap_or(0)
    }
}

#[derive(Debug, Clone, Copy)]
enum CacheMode {
    CacheHit,
    WalIncremental,
    FullDecrypt,
}

impl CacheMode {
    fn as_str(self) -> &'static str {
        match self {
            CacheMode::CacheHit => "cache_hit",
            CacheMode::WalIncremental => "wal_incremental",
            CacheMode::FullDecrypt => "full_decrypt",
        }
    }
}

#[derive(Debug, Clone)]
struct CacheResolve {
    path: PathBuf,
    mode: CacheMode,
}

struct DbCache {
    db_dir: PathBuf,
    cache_dir: PathBuf,
    mtime_file: PathBuf,
    all_keys: HashMap<String, String>,
    inner: HashMap<String, CacheEntry>,
}

#[derive(Clone)]
struct Names {
    map: HashMap<String, String>,
    msg_db_keys: Vec<String>,
    verify_flags: HashMap<String, i64>,
}

#[derive(Debug, Clone)]
struct MessageShard {
    rel_key: String,
    path: PathBuf,
    table: String,
    max_ts: i64,
    cache_mode: CacheMode,
}

pub fn detect_db_storage() -> Option<PathBuf> {
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

pub fn init_from_memory() -> Result<InitData> {
    let db_dir = detect_db_storage().ok_or_else(|| anyhow!("未找到 WOC 微信 db_storage 目录"))?;
    let entries = scan_keys(&db_dir)?;
    if entries.is_empty() {
        bail!("未从内存提取到有效 Message Key");
    }
    let keys = entries
        .iter()
        .map(|entry| (entry.db_name.clone(), entry.enc_key.clone()))
        .collect();
    Ok(InitData { db_dir, keys })
}

pub fn parse_keys_value(value: &Value) -> Result<HashMap<String, String>> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("keys 文件不是 JSON object"))?;
    let mut keys = HashMap::new();
    for (rel_key, item) in obj {
        let enc_key = match item {
            Value::String(s) => s.trim(),
            Value::Object(map) => map.get("enc_key").and_then(Value::as_str).unwrap_or(""),
            _ => "",
        };
        if !enc_key.trim().is_empty() {
            keys.insert(rel_key.replace('\\', "/"), enc_key.trim().to_string());
        }
    }
    if keys.is_empty() {
        bail!("未找到有效 Message Key");
    }
    Ok(keys)
}

pub fn read_keys_file(path: &Path) -> Result<HashMap<String, String>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("读取 keys 文件失败: {}", path.display()))?;
    let value: Value = serde_json::from_str(&raw)
        .with_context(|| format!("解析 keys 文件失败: {}", path.display()))?;
    parse_keys_value(&value)
}

pub fn poll_new_messages(
    db_dir: PathBuf,
    keys: HashMap<String, String>,
    state: Option<HashMap<String, i64>>,
    limit: usize,
    cache_dir: PathBuf,
) -> Result<PollData> {
    let mut db = DbCache::new(db_dir, cache_dir, keys)?;
    let names = load_names(&mut db)?;
    q_new_messages(&mut db, &names, state, limit)
}

pub fn current_session_state(
    db_dir: PathBuf,
    keys: HashMap<String, String>,
    cache_dir: PathBuf,
) -> Result<HashMap<String, i64>> {
    let mut db = DbCache::new(db_dir, cache_dir, keys)?;
    load_session_state(&mut db)
}

fn recipient_display_name(username: &str, nick: &str, remark: &str, alias: &str) -> String {
    let remark = remark.trim();
    if !remark.is_empty() {
        return remark.to_string();
    }
    let nick = nick.trim();
    if !nick.is_empty() {
        return nick.to_string();
    }
    let alias = alias.trim();
    if !alias.is_empty() {
        return alias.to_string();
    }
    username.trim().to_string()
}

fn recipient_from_contact_row(
    username: String,
    nick: String,
    remark: String,
    alias: String,
) -> Recipient {
    let search_uses_remark = !remark.trim().is_empty();
    let display = recipient_display_name(&username, &nick, &remark, &alias);
    let is_group = username.contains("@chatroom");
    Recipient {
        username,
        display,
        is_group,
        search_uses_remark,
    }
}

pub fn resolve_recipient_by_username(
    db_dir: PathBuf,
    keys: HashMap<String, String>,
    cache_dir: PathBuf,
    raw: &str,
) -> Result<Option<Recipient>> {
    let username = raw.trim();
    if username.is_empty() {
        return Ok(None);
    }
    let mut db = DbCache::new(db_dir, cache_dir, keys)?;
    let Some(path) = db.get("contact/contact.db")? else {
        return Ok(None);
    };
    let conn = Connection::open(path)?;
    let recipient = conn
        .query_row(
        "SELECT username, nick_name, remark, alias FROM contact WHERE delete_flag=0 AND username=?1 LIMIT 1",
        [username],
        |row| {
            Ok(recipient_from_contact_row(
                row.get::<_, String>(0)?,
                row.get::<_, String>(1).unwrap_or_default(),
                row.get::<_, String>(2).unwrap_or_default(),
                row.get::<_, String>(3).unwrap_or_default(),
            ))
        },
    )
    .optional()?;
    let Some(recipient) = recipient else {
        return Ok(None);
    };
    if recipient.is_group {
        if !recipient.search_uses_remark {
            bail!("群聊必须设置唯一备注作为发送搜索词");
        }
        let duplicate: Option<String> = conn
            .query_row(
                "SELECT username FROM contact WHERE delete_flag=0 AND remark=?1 AND username<>?2 LIMIT 1",
                [&recipient.display, &recipient.username],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(other) = duplicate {
            bail!(
                "群聊备注不唯一：{} 同时匹配 {} 和 {}",
                recipient.display,
                recipient.username,
                other
            );
        }
    }
    Ok(Some(recipient))
}

fn wx_home() -> PathBuf {
    PathBuf::from(std::env::var("WOC_WX_HOME").unwrap_or_else(|_| "/config".to_string()))
}

fn latest_db_mtime(dir: &Path) -> Option<SystemTime> {
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

fn scan_keys(db_dir: &Path) -> Result<Vec<KeyEntry>> {
    let pids = find_wechat_pids();
    if pids.is_empty() {
        bail!("找不到 WeChat 进程，请确认 WeChat 正在运行");
    }
    let db_salts = collect_db_salts(db_dir);
    if db_salts.is_empty() {
        bail!("未找到加密数据库");
    }

    let mut raw_keys: Vec<(String, String)> = Vec::new();
    for pid in pids {
        let Ok(regions) = parse_maps(pid) else {
            continue;
        };
        let mem_path = format!("/proc/{pid}/mem");
        let Ok(mut mem_file) = fs::File::open(&mem_path) else {
            continue;
        };
        for (start, end) in &regions {
            scan_region(&mut mem_file, *start, *end, &mut raw_keys);
        }
    }

    let mut entries = Vec::new();
    for (key_hex, salt_hex) in &raw_keys {
        for (db_salt, db_name) in &db_salts {
            if salt_hex == db_salt
                && !entries
                    .iter()
                    .any(|entry: &KeyEntry| entry.db_name == *db_name)
            {
                entries.push(KeyEntry {
                    db_name: db_name.clone(),
                    enc_key: key_hex.clone(),
                    salt: salt_hex.clone(),
                });
            }
        }
    }
    Ok(entries)
}

fn find_wechat_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    let Ok(proc_dir) = fs::read_dir("/proc") else {
        return pids;
    };
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Ok(pid) = name_str.parse::<u32>() else {
            continue;
        };
        let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        let cmdline = fs::read(format!("/proc/{pid}/cmdline"))
            .ok()
            .map(|buf| {
                String::from_utf8_lossy(&buf)
                    .replace('\0', " ")
                    .to_lowercase()
            })
            .unwrap_or_default();
        if comm == "wechat"
            || comm == "weixin"
            || comm == "wechatappex"
            || cmdline.contains("/wechat/")
            || cmdline.contains("wechatappex")
        {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    pids.dedup();
    pids
}

fn parse_maps(pid: u32) -> Result<Vec<(u64, u64)>> {
    let maps_path = format!("/proc/{pid}/maps");
    let content =
        fs::read_to_string(&maps_path).with_context(|| format!("读取 {maps_path} 失败"))?;
    let mut regions = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() < 2 {
            continue;
        }
        let perms = parts[1].trim_start();
        if !perms.starts_with("rw") {
            continue;
        }
        let addr_parts: Vec<&str> = parts[0].splitn(2, '-').collect();
        if addr_parts.len() != 2 {
            continue;
        }
        if let (Ok(start), Ok(end)) = (
            u64::from_str_radix(addr_parts[0], 16),
            u64::from_str_radix(addr_parts[1], 16),
        ) {
            regions.push((start, end));
        }
    }
    Ok(regions)
}

fn scan_region(mem: &mut fs::File, start: u64, end: u64, results: &mut Vec<(String, String)>) {
    let total_len = (end - start) as usize;
    let overlap = HEX_PATTERN_LEN + 3;
    let mut offset = 0usize;
    while offset < total_len {
        let chunk_size = std::cmp::min(CHUNK_SIZE, total_len - offset);
        let addr = start + offset as u64;
        if mem.seek(SeekFrom::Start(addr)).is_err() {
            break;
        }
        let mut buf = vec![0u8; chunk_size];
        match mem.read(&mut buf) {
            Ok(n) if n > 0 => {
                buf.truncate(n);
                search_pattern(&buf, results);
            }
            _ => {}
        }
        if chunk_size > overlap {
            offset += chunk_size - overlap;
        } else {
            offset += chunk_size;
        }
    }
}

fn search_pattern(buf: &[u8], results: &mut Vec<(String, String)>) {
    let total = HEX_PATTERN_LEN + 3;
    if buf.len() < total {
        return;
    }
    let mut i = 0;
    while i + total <= buf.len() {
        if buf[i] != b'x' || buf[i + 1] != b'\'' {
            i += 1;
            continue;
        }
        let hex_start = i + 2;
        let all_hex = buf[hex_start..hex_start + HEX_PATTERN_LEN]
            .iter()
            .all(|c| c.is_ascii_hexdigit());
        if !all_hex || buf[hex_start + HEX_PATTERN_LEN] != b'\'' {
            i += 1;
            continue;
        }
        let key_hex = String::from_utf8_lossy(&buf[hex_start..hex_start + 64]).to_lowercase();
        let salt_hex = String::from_utf8_lossy(&buf[hex_start + 64..hex_start + 96]).to_lowercase();
        if !results.iter().any(|(k, s)| k == &key_hex && s == &salt_hex) {
            results.push((key_hex, salt_hex));
        }
        i += total;
    }
}

fn collect_db_salts(db_dir: &Path) -> Vec<(String, String)> {
    let mut result = Vec::new();
    collect_recursive(db_dir, db_dir, &mut result);
    result
}

fn collect_recursive(base: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_recursive(base, &path, out);
        } else if path.extension().map(|e| e == "db").unwrap_or(false) {
            if let Some(salt) = read_db_salt(&path) {
                if let Ok(rel) = path.strip_prefix(base) {
                    out.push((salt, rel.to_string_lossy().replace('\\', "/")));
                }
            }
        }
    }
}

fn read_db_salt(path: &Path) -> Option<String> {
    let mut buf = [0u8; 16];
    let mut f = fs::File::open(path).ok()?;
    f.read_exact(&mut buf).ok()?;
    if &buf[..15] == b"SQLite format 3" {
        return None;
    }
    Some(hex_encode(&buf))
}

impl DbCache {
    fn new(db_dir: PathBuf, cache_dir: PathBuf, all_keys: HashMap<String, String>) -> Result<Self> {
        fs::create_dir_all(&cache_dir)?;
        let mtime_file = cache_dir.join("_mtimes.json");
        let mut cache = Self {
            db_dir,
            cache_dir,
            mtime_file,
            all_keys,
            inner: HashMap::new(),
        };
        cache.load_persistent();
        Ok(cache)
    }

    fn db_dir(&self) -> &Path {
        &self.db_dir
    }

    fn cache_file_path(&self, rel_key: &str) -> PathBuf {
        let hash = format!("{:x}", md5::compute(rel_key.as_bytes()));
        self.cache_dir.join(format!("{hash}.db"))
    }

    fn load_persistent(&mut self) {
        let Ok(content) = fs::read_to_string(&self.mtime_file) else {
            return;
        };
        let Ok(saved) = serde_json::from_str::<HashMap<String, MtimeEntry>>(&content) else {
            return;
        };
        for (rel_key, entry) in saved {
            let dec_path = PathBuf::from(&entry.path);
            if !dec_path.exists() {
                continue;
            }
            let db_path = self.db_path(&rel_key);
            if mtime_nanos(&db_path) == entry.db_mt {
                self.inner.insert(
                    rel_key,
                    CacheEntry {
                        db_mtime: entry.db_mt,
                        wal_mtime: entry.wal_mt,
                        decrypted_path: dec_path,
                    },
                );
            }
        }
    }

    fn save_persistent(&self) {
        let data: HashMap<String, MtimeEntry> = self
            .inner
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    MtimeEntry {
                        db_mt: v.db_mtime,
                        wal_mt: v.wal_mtime,
                        path: v.decrypted_path.to_string_lossy().into_owned(),
                    },
                )
            })
            .collect();
        if let Ok(json) = serde_json::to_string_pretty(&data) {
            let _ = fs::write(&self.mtime_file, json);
        }
    }

    fn db_path(&self, rel_key: &str) -> PathBuf {
        self.db_dir.join(
            rel_key
                .replace('\\', std::path::MAIN_SEPARATOR_STR)
                .replace('/', std::path::MAIN_SEPARATOR_STR),
        )
    }

    fn get(&mut self, rel_key: &str) -> Result<Option<PathBuf>> {
        Ok(self.get_with_mode(rel_key)?.map(|r| r.path))
    }

    fn get_with_mode(&mut self, rel_key: &str) -> Result<Option<CacheResolve>> {
        let Some(enc_key_hex) = self.all_keys.get(rel_key).cloned() else {
            return Ok(None);
        };
        let db_path = self.db_path(rel_key);
        if !db_path.exists() {
            return Ok(None);
        }
        let wal_path = wal_path_for(&db_path);
        let db_mt = mtime_nanos(&db_path);
        let wal_mt = if wal_path.exists() {
            mtime_nanos(&wal_path)
        } else {
            0
        };
        let enc_key_bytes =
            hex_to_32bytes(&enc_key_hex).with_context(|| format!("密钥格式错误: {rel_key}"))?;

        if let Some(entry) = self.inner.get(rel_key).cloned() {
            if entry.db_mtime == db_mt && entry.decrypted_path.exists() {
                if entry.wal_mtime == wal_mt {
                    return Ok(Some(CacheResolve {
                        path: entry.decrypted_path,
                        mode: CacheMode::CacheHit,
                    }));
                }
                if wal_path.exists() {
                    apply_wal(&wal_path, &entry.decrypted_path, &enc_key_bytes)?;
                }
                self.inner.insert(
                    rel_key.to_string(),
                    CacheEntry {
                        db_mtime: db_mt,
                        wal_mtime: wal_mt,
                        decrypted_path: entry.decrypted_path.clone(),
                    },
                );
                self.save_persistent();
                return Ok(Some(CacheResolve {
                    path: entry.decrypted_path,
                    mode: CacheMode::WalIncremental,
                }));
            }
        }

        let out_path = self.cache_file_path(rel_key);
        full_decrypt(&db_path, &out_path, &enc_key_bytes)?;
        if wal_path.exists() {
            apply_wal(&wal_path, &out_path, &enc_key_bytes)?;
        }
        self.inner.insert(
            rel_key.to_string(),
            CacheEntry {
                db_mtime: db_mt,
                wal_mtime: wal_mt,
                decrypted_path: out_path.clone(),
            },
        );
        self.save_persistent();
        Ok(Some(CacheResolve {
            path: out_path,
            mode: CacheMode::FullDecrypt,
        }))
    }
}

fn load_names(db: &mut DbCache) -> Result<Names> {
    let mut map = HashMap::new();
    let mut verify_flags = HashMap::new();
    if let Some(path) = db.get("contact/contact.db")? {
        let conn = Connection::open(path)?;
        if let Ok(mut stmt) =
            conn.prepare("SELECT username, nick_name, remark, verify_flag FROM contact")
        {
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1).unwrap_or_default(),
                    row.get::<_, String>(2).unwrap_or_default(),
                    row.get::<_, i64>(3).unwrap_or(0),
                ))
            })?;
            for row in rows.flatten() {
                let (uname, nick, remark, vf) = row;
                let display = if !remark.is_empty() {
                    remark
                } else if !nick.is_empty() {
                    nick
                } else {
                    uname.clone()
                };
                verify_flags.insert(uname.clone(), vf);
                map.insert(uname, display);
            }
        };
    }
    let mut msg_db_keys: Vec<String> = db
        .all_keys
        .keys()
        .filter(|key| key.starts_with("message/") && is_message_shard_key(key))
        .cloned()
        .collect();
    msg_db_keys.sort();
    Ok(Names {
        map,
        msg_db_keys,
        verify_flags,
    })
}

fn q_new_messages(
    db: &mut DbCache,
    names: &Names,
    state: Option<HashMap<String, i64>>,
    limit: usize,
) -> Result<PollData> {
    let fallback_ts = unix_now() - 86400;
    let session_ts_map = load_session_state(db)?;
    let changed: Vec<(String, i64)> = session_ts_map
        .iter()
        .filter(|(uname, ts)| {
            let last_known = state
                .as_ref()
                .and_then(|m| m.get(*uname))
                .copied()
                .unwrap_or(fallback_ts);
            **ts > last_known
        })
        .map(|(uname, ts)| (uname.clone(), *ts))
        .collect();
    let unknown_shards = discover_unknown_shards(db.db_dir(), &names.msg_db_keys);

    if changed.is_empty() {
        return Ok(PollData {
            messages: Vec::new(),
            new_state: session_ts_map,
            meta: json!({
                "shards_scanned": 0,
                "shards_hit": 0,
                "unknown_shards": unknown_shards,
                "status": "windowed",
                "cache_mode_per_shard": {},
                "shard_paths": {},
            }),
        });
    }

    let per_table_limit = limit.saturating_mul(5).max(200);
    let mut all_msgs = Vec::new();
    let mut scanned_rel_keys = HashSet::new();
    let mut hit_rel_keys = HashSet::new();
    let mut cache_modes = serde_json::Map::new();
    let mut shard_paths = serde_json::Map::new();

    for (uname, _) in &changed {
        let since_ts = state
            .as_ref()
            .and_then(|m| m.get(uname))
            .copied()
            .unwrap_or(fallback_ts);
        let shards = find_msg_shards(db, names, uname)?;
        if shards.is_empty() {
            continue;
        }
        for shard in &shards {
            scanned_rel_keys.insert(shard.rel_key.clone());
            cache_modes.insert(
                shard.rel_key.clone(),
                Value::String(shard.cache_mode.as_str().to_string()),
            );
            shard_paths.insert(
                shard.rel_key.clone(),
                Value::String(shard.path.to_string_lossy().into_owned()),
            );
        }

        let display = names.display(uname);
        let chat_type = chat_type_of(uname, names);
        let is_group = chat_type == "group";
        for shard in &shards {
            let msgs = query_new_table(
                &shard.path,
                &shard.table,
                uname,
                &display,
                chat_type,
                is_group,
                &names.map,
                since_ts,
                per_table_limit,
            )
            .unwrap_or_else(|e| {
                eprintln!("[new-messages] skip {}: {}", shard.table, e);
                Vec::new()
            });
            if !msgs.is_empty() {
                hit_rel_keys.insert(shard.rel_key.clone());
            }
            all_msgs.extend(msgs);
        }
    }

    let all_msgs = select_poll_messages(all_msgs, limit);

    let mut returned_max_ts: HashMap<String, i64> = HashMap::new();
    for msg in &all_msgs {
        if let (Some(u), Some(ts)) = (msg["username"].as_str(), msg["timestamp"].as_i64()) {
            let current = returned_max_ts.entry(u.to_string()).or_insert(0);
            if ts > *current {
                *current = ts;
            }
        }
    }
    let new_state = next_poll_state(
        session_ts_map,
        &changed,
        state.as_ref(),
        &returned_max_ts,
        fallback_ts,
    );

    Ok(PollData {
        messages: all_msgs,
        new_state,
        meta: json!({
            "shards_scanned": scanned_rel_keys.len(),
            "shards_hit": hit_rel_keys.len(),
            "unknown_shards": unknown_shards,
            "status": "windowed",
            "cache_mode_per_shard": cache_modes,
            "shard_paths": shard_paths,
        }),
    })
}

fn load_session_state(db: &mut DbCache) -> Result<HashMap<String, i64>> {
    let session_path = db
        .get("session/session.db")?
        .ok_or_else(|| anyhow!("无法解密 session.db"))?;
    let conn = Connection::open(session_path)?;
    let mut stmt =
        conn.prepare("SELECT username, last_timestamp FROM SessionTable WHERE last_timestamp > 0")?;
    let sessions = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1).unwrap_or(0)))
        })?
        .filter_map(|row| row.ok())
        .collect();
    Ok(sessions)
}

fn find_msg_shards(db: &mut DbCache, names: &Names, username: &str) -> Result<Vec<MessageShard>> {
    let table_name = format!("Msg_{:x}", md5::compute(username.as_bytes()));
    let mut results = Vec::new();
    for rel_key in &names.msg_db_keys {
        let Some(resolved) = db.get_with_mode(rel_key)? else {
            continue;
        };
        let conn = Connection::open(&resolved.path)?;
        let table_exists: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                [&table_name],
                |row| row.get(0),
            )
            .ok()
            .flatten();
        if table_exists.is_none() {
            continue;
        }
        let max_ts: Option<i64> = conn
            .query_row(
                &format!("SELECT MAX(create_time) FROM [{}]", table_name),
                [],
                |row| row.get(0),
            )
            .ok()
            .flatten();
        if let Some(ts) = max_ts {
            results.push(MessageShard {
                rel_key: rel_key.clone(),
                path: resolved.path,
                table: table_name.clone(),
                max_ts: ts,
                cache_mode: resolved.mode,
            });
        }
    }
    results.sort_by_key(|s| std::cmp::Reverse(s.max_ts));
    Ok(results)
}

#[allow(clippy::too_many_arguments)]
fn query_new_table(
    db_path: &Path,
    table: &str,
    username: &str,
    display: &str,
    chat_type: &str,
    is_group: bool,
    names: &HashMap<String, String>,
    since_ts: i64,
    limit: usize,
) -> Result<Vec<Value>> {
    let conn = Connection::open(db_path)?;
    let id2u = load_id2u(&conn);
    let sql = format!(
        "SELECT local_id, local_type, create_time, real_sender_id,
                message_content, WCDB_CT_message_content
         FROM [{}] WHERE create_time > ? ORDER BY create_time ASC LIMIT ?",
        table
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows: Vec<_> = stmt
        .query_map(rusqlite::params![since_ts, limit as i64], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                get_content_bytes(row, 4),
                row.get::<_, i64>(5).unwrap_or(0),
            ))
        })?
        .filter_map(|row| row.ok())
        .collect();

    let mut out = Vec::new();
    let empty_group_names = HashMap::new();
    for (local_id, local_type, ts, real_sender_id, content_bytes, ct) in rows {
        let content = decompress_message(&content_bytes, ct);
        let sender = sender_label(
            real_sender_id,
            &content,
            is_group,
            username,
            &id2u,
            names,
            &empty_group_names,
        );
        let text = fmt_content(local_id, local_type, &content, is_group);
        let quote = quote_for_message(local_type, &content, is_group);
        let message_type = fmt_type(local_type, quote.as_ref());
        let mut msg = json!({
            "chat": display,
            "username": username,
            "is_group": is_group,
            "chat_type": chat_type,
            "timestamp": ts,
            "time": ts.to_string(),
            "sender": sender,
            "content": text,
            "type": message_type,
            "local_id": local_id,
            "local_type": local_type,
            "base_type": base_type(local_type),
        });
        if is_text_message(local_type) {
            msg["kind"] = Value::String("text".to_string());
            msg["text"] = msg["content"].clone();
        }
        if let Some(quote) = quote {
            msg["kind"] = Value::String("quote".to_string());
            msg["text"] = msg["content"].clone();
            msg["quote"] = json!({
                "type": fmt_base_type(quote.base_type()),
                "raw_type": quote.msg_type,
                "svrid": quote.svrid,
                "fromusr": quote.fromusr,
                "chatusr": quote.chatusr,
                "displayname": quote.displayname,
                "content": quote.content,
                "createtime": quote.createtime_i64(),
                "raw_createtime": quote.createtime,
            });
        }
        if let Some(url) = appmsg_url_for_message(local_type, &content) {
            msg["url"] = Value::String(url);
        }
        out.push(msg);
    }
    Ok(out)
}

impl Names {
    fn display(&self, username: &str) -> String {
        self.map
            .get(username)
            .cloned()
            .unwrap_or_else(|| username.to_string())
    }

    fn is_verified(&self, username: &str) -> bool {
        self.verify_flags.get(username).copied().unwrap_or(0) != 0
    }
}

fn chat_type_of(username: &str, names: &Names) -> &'static str {
    if username.contains("@chatroom") {
        return "group";
    }
    if username == "brandsessionholder" || username == "@placeholder_foldgroup" {
        return "folded";
    }
    if names.is_verified(username) || username.starts_with("gh_") || username.starts_with("biz_") {
        return "official_account";
    }
    if username.starts_with('@') {
        return "official_account";
    }
    "private"
}

fn load_id2u(conn: &Connection) -> HashMap<i64, String> {
    let mut map = HashMap::new();
    if let Ok(mut stmt) = conn.prepare("SELECT rowid, user_name FROM Name2Id") {
        let _ = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map(|rows| {
                for row in rows.flatten() {
                    map.insert(row.0, row.1);
                }
            });
    }
    map
}

fn sender_label(
    real_sender_id: i64,
    content: &str,
    is_group: bool,
    chat_username: &str,
    id2u: &HashMap<i64, String>,
    names: &HashMap<String, String>,
    group_nicknames: &HashMap<String, String>,
) -> String {
    let sender_uname = id2u.get(&real_sender_id).cloned().unwrap_or_default();
    if is_group {
        if !sender_uname.is_empty() && sender_uname != chat_username {
            return sender_display(&sender_uname, names, group_nicknames);
        }
        if content.contains(":\n") {
            let raw = content.splitn(2, ":\n").next().unwrap_or("");
            return sender_display(raw, names, group_nicknames);
        }
        return String::new();
    }
    if !sender_uname.is_empty() && sender_uname != chat_username {
        return names.get(&sender_uname).cloned().unwrap_or(sender_uname);
    }
    String::new()
}

fn sender_display(
    username: &str,
    names: &HashMap<String, String>,
    group_nicknames: &HashMap<String, String>,
) -> String {
    group_nicknames
        .get(username)
        .or_else(|| names.get(username))
        .cloned()
        .unwrap_or_else(|| username.to_string())
}

fn get_content_bytes(row: &rusqlite::Row<'_>, idx: usize) -> Vec<u8> {
    row.get::<_, Vec<u8>>(idx)
        .or_else(|_| row.get::<_, String>(idx).map(|s| s.into_bytes()))
        .unwrap_or_default()
}

fn decompress_message(data: &[u8], ct: i64) -> String {
    if ct == 4 && !data.is_empty() {
        if let Ok(dec) = zstd::decode_all(data) {
            return String::from_utf8_lossy(&dec).into_owned();
        }
    }
    String::from_utf8_lossy(data).into_owned()
}

fn base_type(t: i64) -> i64 {
    (t as u64 & 0xFFFFFFFF) as i64
}

fn fmt_type(t: i64, quote: Option<&ReferMsg>) -> String {
    if quote.is_some() {
        return "引用".into();
    }
    fmt_base_type(base_type(t))
}

fn fmt_base_type(base: i64) -> String {
    match base {
        1 => "文本".into(),
        3 => "图片".into(),
        34 => "语音".into(),
        42 => "名片".into(),
        43 => "视频".into(),
        47 => "表情".into(),
        48 => "位置".into(),
        49 => "链接/文件".into(),
        50 => "通话".into(),
        10000 => "系统".into(),
        10002 => "撤回".into(),
        _ => format!("type={base}"),
    }
}

fn fmt_content(local_id: i64, local_type: i64, content: &str, is_group: bool) -> String {
    let base = base_type(local_type);
    match base {
        3 => return format!("[图片] local_id={local_id}"),
        34 => return "[语音]".into(),
        43 => return "[视频]".into(),
        47 => return "[表情]".into(),
        50 => return "[通话]".into(),
        10000 => return parse_sysmsg(content).unwrap_or_else(|| "[系统消息]".into()),
        10002 => return parse_revoke(content).unwrap_or_else(|| "[撤回了一条消息]".into()),
        _ => {}
    }
    let text = strip_group_prefix(content, is_group);
    if base == 49 && text.contains("<appmsg") {
        if let Some(parsed) = parse_appmsg(text) {
            return parsed;
        }
    }
    text.to_string()
}

fn strip_group_prefix(content: &str, is_group: bool) -> &str {
    if is_group && content.contains(":\n") {
        content.splitn(2, ":\n").nth(1).unwrap_or(content)
    } else {
        content
    }
}

fn parse_revoke(xml: &str) -> Option<String> {
    let inner = extract_xml_text(xml, "content")?;
    Some(if inner.is_empty() {
        "[撤回了一条消息]".into()
    } else {
        format!("[撤回] {}", inner.chars().take(30).collect::<String>())
    })
}

fn parse_sysmsg(xml: &str) -> Option<String> {
    if let Some(s) = extract_xml_text(xml, "content") {
        if !s.is_empty() {
            return Some(format!("[系统] {}", s.chars().take(50).collect::<String>()));
        }
    }
    if !xml.starts_with('<') {
        return Some(format!(
            "[系统] {}",
            xml.chars().take(50).collect::<String>()
        ));
    }
    Some("[系统消息]".into())
}

fn parse_appmsg(text: &str) -> Option<String> {
    if let Some(quote) = parse_refermsg(text) {
        return Some(format_quote_content(text, &quote));
    }
    let title = extract_xml_text(text, "title").unwrap_or_default();
    let app_name = extract_xml_text(text, "appname").unwrap_or_default();
    if title.is_empty() && app_name.is_empty() {
        None
    } else if app_name.is_empty() {
        Some(format!("[链接] {title}"))
    } else if title.is_empty() {
        Some(format!("[链接] {app_name}"))
    } else {
        Some(format!("[链接] {title} - {app_name}"))
    }
}

fn quote_for_message(local_type: i64, content: &str, is_group: bool) -> Option<ReferMsg> {
    if base_type(local_type) != 49 {
        return None;
    }
    parse_refermsg(strip_group_prefix(content, is_group))
}

fn parse_refermsg(text: &str) -> Option<ReferMsg> {
    let refer_xml = extract_xml_text(text, "refermsg")?;
    Some(ReferMsg {
        msg_type: clean_xml_text(extract_xml_text(&refer_xml, "type").unwrap_or_default()),
        svrid: clean_xml_text(extract_xml_text(&refer_xml, "svrid").unwrap_or_default()),
        fromusr: clean_xml_text(extract_xml_text(&refer_xml, "fromusr").unwrap_or_default()),
        chatusr: clean_xml_text(extract_xml_text(&refer_xml, "chatusr").unwrap_or_default()),
        displayname: clean_xml_text(
            extract_xml_text(&refer_xml, "displayname").unwrap_or_default(),
        ),
        content: clean_xml_text(extract_xml_text(&refer_xml, "content").unwrap_or_default()),
        createtime: clean_xml_text(extract_xml_text(&refer_xml, "createtime").unwrap_or_default()),
    })
}

fn format_quote_content(text: &str, quote: &ReferMsg) -> String {
    let title = clean_xml_text(extract_xml_text(text, "title").unwrap_or_default());
    let mut out = if title.is_empty() {
        "[引用]".to_string()
    } else {
        format!("[引用] {title}")
    };
    let quoted_sender = if quote.displayname.is_empty() {
        quote.chatusr.as_str()
    } else {
        quote.displayname.as_str()
    };
    if !quoted_sender.is_empty() || !quote.content.is_empty() {
        out.push_str("\n> ");
        if !quoted_sender.is_empty() {
            out.push_str(quoted_sender);
            out.push_str(": ");
        }
        out.push_str(&quote.content);
    }
    out
}

fn clean_xml_text(s: String) -> String {
    unescape_html(strip_xml_cdata(s.trim())).trim().to_string()
}

fn is_text_message(t: i64) -> bool {
    base_type(t) == 1
}

fn select_poll_messages(mut messages: Vec<Value>, limit: usize) -> Vec<Value> {
    if messages.len() <= limit {
        messages.sort_by_key(|m| m["timestamp"].as_i64().unwrap_or(0));
        return messages;
    }

    messages.sort_by(|a, b| {
        let a_ts = a["timestamp"].as_i64().unwrap_or(0);
        let b_ts = b["timestamp"].as_i64().unwrap_or(0);
        a_ts.cmp(&b_ts).then_with(|| {
            a["username"]
                .as_str()
                .unwrap_or("")
                .cmp(b["username"].as_str().unwrap_or(""))
        })
    });

    let mut buckets: HashMap<String, VecDeque<Value>> = HashMap::new();
    for msg in messages {
        let username = msg["username"].as_str().unwrap_or("").to_string();
        buckets.entry(username).or_default().push_back(msg);
    }
    let mut keys: Vec<String> = buckets.keys().cloned().collect();
    keys.sort_by_key(|key| {
        buckets
            .get(key)
            .and_then(|bucket| bucket.front())
            .and_then(|msg| msg["timestamp"].as_i64())
            .unwrap_or(0)
    });

    let mut selected = Vec::with_capacity(limit);
    while selected.len() < limit && !keys.is_empty() {
        let mut remaining = Vec::new();
        for key in keys {
            if selected.len() >= limit {
                remaining.push(key);
                continue;
            }
            if let Some(bucket) = buckets.get_mut(&key) {
                if let Some(msg) = bucket.pop_front() {
                    selected.push(msg);
                }
                if !bucket.is_empty() {
                    remaining.push(key);
                }
            }
        }
        keys = remaining;
    }
    selected.sort_by_key(|m| m["timestamp"].as_i64().unwrap_or(0));
    selected
}

fn next_poll_state(
    mut session_ts_map: HashMap<String, i64>,
    changed: &[(String, i64)],
    previous_state: Option<&HashMap<String, i64>>,
    returned_max_ts: &HashMap<String, i64>,
    fallback_ts: i64,
) -> HashMap<String, i64> {
    for (uname, _) in changed {
        let prev = previous_state
            .and_then(|state| state.get(uname))
            .copied()
            .unwrap_or(fallback_ts);
        let next_ts = returned_max_ts.get(uname).copied().unwrap_or(prev);
        session_ts_map.insert(uname.clone(), next_ts);
    }
    session_ts_map
}

fn appmsg_url_for_message(local_type: i64, content: &str) -> Option<String> {
    if base_type(local_type) != 49 || !content.contains("<appmsg") {
        return None;
    }
    let url = extract_xml_text(content, "url")
        .or_else(|| extract_xml_text(content, "url1"))
        .map(|s| unescape_html(strip_xml_cdata(&s)))?;
    if url.starts_with("http://") || url.starts_with("https://") {
        Some(url)
    } else {
        None
    }
}

fn extract_xml_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)?;
    let content_start = start + open.len();
    let end = xml[content_start..].find(&close)?;
    Some(xml[content_start..content_start + end].trim().to_string())
}

fn strip_xml_cdata(s: &str) -> &str {
    s.strip_prefix("<![CDATA[")
        .and_then(|inner| inner.strip_suffix("]]>"))
        .unwrap_or(s)
}

fn unescape_html(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn discover_unknown_shards(db_dir: &Path, known: &[String]) -> Vec<String> {
    let known_set: HashSet<String> = known.iter().map(|k| k.replace('\\', "/")).collect();
    let msg_dir = db_dir.join("message");
    let Ok(entries) = fs::read_dir(&msg_dir) else {
        return Vec::new();
    };
    let mut unknown = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !is_message_shard(name_str) {
            continue;
        }
        let rel = format!("message/{name_str}");
        if !known_set.contains(&rel) {
            unknown.push(rel);
        }
    }
    unknown.sort();
    unknown
}

fn is_message_shard_key(rel_key: &str) -> bool {
    rel_key
        .rsplit('/')
        .next()
        .map(is_message_shard)
        .unwrap_or(false)
}

fn is_message_shard(file_name: &str) -> bool {
    if !file_name.starts_with("message_") || !file_name.ends_with(".db") {
        return false;
    }
    if file_name.contains("_fts") || file_name.contains("_resource") {
        return false;
    }
    let stem = &file_name["message_".len()..file_name.len() - ".db".len()];
    !stem.is_empty() && stem.chars().all(|c| c.is_ascii_digit())
}

fn full_decrypt(db_path: &Path, out_path: &Path, enc_key: &[u8; 32]) -> Result<()> {
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut input = fs::File::open(db_path)?;
    let file_size = input.metadata()?.len() as usize;
    if file_size == 0 {
        bail!("数据库文件为空: {}", db_path.display());
    }
    let mut output = fs::File::create(out_path)?;
    let total_pages = file_size.div_ceil(PAGE_SZ);
    let mut page_buf = vec![0u8; PAGE_SZ];
    for pgno in 1..=total_pages {
        let page_start = (pgno - 1) * PAGE_SZ;
        let bytes_remaining = file_size.saturating_sub(page_start);
        let expected = bytes_remaining.min(PAGE_SZ);
        input.read_exact(&mut page_buf[..expected])?;
        if expected < PAGE_SZ {
            page_buf[expected..].fill(0);
        }
        let dec = decrypt_page(enc_key, &page_buf, pgno as u32)?;
        output.write_all(&dec)?;
    }
    Ok(())
}

fn apply_wal(wal_path: &Path, out_path: &Path, enc_key: &[u8; 32]) -> Result<()> {
    if !wal_path.exists() {
        return Ok(());
    }
    let wal_data = fs::read(wal_path)?;
    if wal_data.len() <= WAL_HDR_SZ {
        return Ok(());
    }
    let s1 = u32::from_be_bytes(wal_data[16..20].try_into().unwrap());
    let s2 = u32::from_be_bytes(wal_data[20..24].try_into().unwrap());
    let frame_size = WAL_FRAME_HDR + PAGE_SZ;
    let frame_area = &wal_data[WAL_HDR_SZ..];
    let mut db_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(out_path)?;
    let mut pos = 0usize;
    while pos + frame_size <= frame_area.len() {
        let fh = &frame_area[pos..pos + WAL_FRAME_HDR];
        let page_data = &frame_area[pos + WAL_FRAME_HDR..pos + frame_size];
        let pgno = u32::from_be_bytes(fh[0..4].try_into().unwrap());
        let fs1 = u32::from_be_bytes(fh[8..12].try_into().unwrap());
        let fs2 = u32::from_be_bytes(fh[12..16].try_into().unwrap());
        pos += frame_size;
        if pgno == 0 || pgno > 1_000_000 || fs1 != s1 || fs2 != s2 {
            continue;
        }
        let mut page_buf = page_data.to_vec();
        if page_buf.len() < PAGE_SZ {
            page_buf.resize(PAGE_SZ, 0);
        }
        let dec = decrypt_page(enc_key, &page_buf, if pgno == 1 { 2 } else { pgno })?;
        let file_offset = (pgno as u64 - 1) * PAGE_SZ as u64;
        db_file.seek(SeekFrom::Start(file_offset))?;
        db_file.write_all(&dec)?;
    }
    Ok(())
}

fn decrypt_page(enc_key: &[u8; 32], page_data: &[u8], pgno: u32) -> Result<Vec<u8>> {
    if page_data.len() < PAGE_SZ {
        bail!("页面数据不足 {} 字节", PAGE_SZ);
    }
    let iv_offset = PAGE_SZ - RESERVE_SZ;
    let iv: &[u8; 16] = page_data[iv_offset..iv_offset + 16].try_into().unwrap();
    let mut result = vec![0u8; PAGE_SZ];
    if pgno == 1 {
        let enc = &page_data[SALT_SZ..PAGE_SZ - RESERVE_SZ];
        let dec = aes_cbc_decrypt(enc_key, iv, enc)?;
        result[..16].copy_from_slice(SQLITE_HDR);
        result[16..PAGE_SZ - RESERVE_SZ].copy_from_slice(&dec);
    } else {
        let enc = &page_data[..PAGE_SZ - RESERVE_SZ];
        let dec = aes_cbc_decrypt(enc_key, iv, enc)?;
        result[..PAGE_SZ - RESERVE_SZ].copy_from_slice(&dec);
    }
    Ok(result)
}

fn aes_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() || data.len() % 16 != 0 {
        bail!("密文长度不是 AES 块大小的倍数: {}", data.len());
    }
    let mut blocks: Vec<Block> = data.chunks_exact(16).map(Block::clone_from_slice).collect();
    Aes256CbcDec::new(key.into(), iv.into()).decrypt_blocks_mut(&mut blocks);
    Ok(blocks.iter().flat_map(|b| b.iter().copied()).collect())
}

fn wal_path_for(db_path: &Path) -> PathBuf {
    let mut name = db_path.file_name().unwrap_or_default().to_os_string();
    name.push("-wal");
    db_path.with_file_name(name)
}

fn mtime_nanos(path: &Path) -> u64 {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .map(|t| t.duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64)
        .unwrap_or(0)
}

fn hex_to_32bytes(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        bail!("密钥 hex 长度应为 64，实际为 {}", s.len());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("非法 hex 字符 at {}", i * 2))?;
    }
    Ok(out)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_from_contact_keeps_internal_username() {
        let recipient = recipient_from_contact_row(
            "24933085811@chatroom".to_string(),
            "姑姑的钻粉只此一群❤️".to_string(),
            String::new(),
            String::new(),
        );
        assert_eq!(recipient.username, "24933085811@chatroom");
        assert_eq!(recipient.display, "姑姑的钻粉只此一群❤️");
        assert!(recipient.is_group);
    }

    #[test]
    fn recipient_display_prefers_remark_then_nick_then_alias() {
        assert_eq!(
            recipient_display_name("wxid_1", "昵称", "备注", "alias"),
            "备注"
        );
        assert_eq!(
            recipient_display_name("wxid_1", "昵称", "", "alias"),
            "昵称"
        );
        assert_eq!(recipient_display_name("wxid_1", "", "", "alias"), "alias");
        assert_eq!(recipient_display_name("wxid_1", "", "", ""), "wxid_1");
    }

    #[test]
    fn poll_state_does_not_ack_unreturned_changed_sessions() {
        let session_ts = HashMap::from([
            ("busy@chatroom".to_string(), 2000),
            ("target@chatroom".to_string(), 2100),
        ]);
        let changed = vec![
            ("busy@chatroom".to_string(), 2000),
            ("target@chatroom".to_string(), 2100),
        ];
        let returned = HashMap::from([("busy@chatroom".to_string(), 1500)]);

        let state = next_poll_state(session_ts, &changed, None, &returned, 1000);

        assert_eq!(state.get("busy@chatroom"), Some(&1500));
        assert_eq!(state.get("target@chatroom"), Some(&1000));
    }

    #[test]
    fn poll_selection_keeps_low_volume_session_when_busy_session_overflows_limit() {
        let mut messages = Vec::new();
        for i in 0..10 {
            messages.push(json!({
                "username": "busy@chatroom",
                "timestamp": 1000 + i,
                "content": format!("busy {i}"),
            }));
        }
        messages.push(json!({
            "username": "target@chatroom",
            "timestamp": 1005,
            "content": "target",
        }));

        let selected = select_poll_messages(messages, 5);

        assert_eq!(selected.len(), 5);
        assert!(selected
            .iter()
            .any(|msg| msg["username"].as_str() == Some("target@chatroom")));
    }

    #[test]
    fn poll_state_keeps_previous_position_for_unreturned_sessions() {
        let session_ts = HashMap::from([
            ("busy@chatroom".to_string(), 2000),
            ("target@chatroom".to_string(), 2100),
        ]);
        let previous = HashMap::from([
            ("busy@chatroom".to_string(), 1200),
            ("target@chatroom".to_string(), 1800),
        ]);
        let changed = vec![
            ("busy@chatroom".to_string(), 2000),
            ("target@chatroom".to_string(), 2100),
        ];
        let returned = HashMap::from([("busy@chatroom".to_string(), 1500)]);

        let state = next_poll_state(session_ts, &changed, Some(&previous), &returned, 1000);

        assert_eq!(state.get("busy@chatroom"), Some(&1500));
        assert_eq!(state.get("target@chatroom"), Some(&1800));
    }

    #[test]
    fn appmsg_quote_keeps_referenced_message() {
        let xml = r#"
<?xml version="1.0"?>
<msg>
  <appmsg appid="" sdkver="0">
    <title>@私云虾虾</title>
    <type>57</type>
    <refermsg>
      <chatusr>che006</chatusr>
      <type>1</type>
      <createtime>1781610131</createtime>
      <displayname>青椒Der(大学青年教师，不是大师)</displayname>
      <svrid>7318462845630259071</svrid>
      <fromusr>24933085811@chatroom</fromusr>
      <content>虾虾，这个视频的标题是什么：https://www.youtube.com/watch?v=P3W5L3HGBgg</content>
    </refermsg>
  </appmsg>
</msg>
"#;

        let quote = parse_refermsg(xml).expect("quote should parse");

        assert_eq!(quote.msg_type, "1");
        assert_eq!(quote.chatusr, "che006");
        assert_eq!(quote.displayname, "青椒Der(大学青年教师，不是大师)");
        assert_eq!(
            quote.content,
            "虾虾，这个视频的标题是什么：https://www.youtube.com/watch?v=P3W5L3HGBgg"
        );
        assert_eq!(
            parse_appmsg(xml),
            Some("[引用] @私云虾虾\n> 青椒Der(大学青年教师，不是大师): 虾虾，这个视频的标题是什么：https://www.youtube.com/watch?v=P3W5L3HGBgg".to_string())
        );
    }
}
