use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

const MAX_LIMITER_ENTRIES: usize = 50_000;
const MAX_LIMITER_KEY_BYTES: usize = 128;

static DISABLE_RATE_LIMIT: OnceLock<bool> = OnceLock::new();

fn rate_limit_disabled() -> bool {
    *DISABLE_RATE_LIMIT
        .get_or_init(|| std::env::var("SERES_DISABLE_RATE_LIMIT").as_deref() == Ok("1"))
}

fn normalize_limiter_key(raw: String) -> String {
    if raw.len() <= MAX_LIMITER_KEY_BYTES {
        return raw;
    }
    let digest = Sha256::digest(raw.as_bytes());
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

struct RateEntry {
    hits: Vec<Instant>,
    expires_at: Instant,
}

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    limiter: Arc<Mutex<HashMap<String, RateEntry>>>,
    typing: Arc<Mutex<HashMap<(String, String), Instant>>>,
}

impl AppState {
    pub fn new(db: SqlitePool) -> Self {
        Self {
            db,
            limiter: Arc::new(Mutex::new(HashMap::new())),
            typing: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn rate_limited(&self, key: impl Into<String>, limit: usize, window_secs: u64) -> bool {
        if rate_limit_disabled() {
            return false;
        }
        let key = normalize_limiter_key(key.into());
        let now = Instant::now();
        let window = Duration::from_secs(window_secs);
        let mut map = self
            .limiter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(entry) = map.get_mut(&key) {
            entry
                .hits
                .retain(|at| now.saturating_duration_since(*at) < window);
            if entry.hits.len() >= limit {
                return true;
            }
            entry.hits.push(now);
            entry.expires_at = now + window;
            return false;
        }
        if limit == 0 {
            return true;
        }
        if map.len() >= MAX_LIMITER_ENTRIES {
            map.retain(|_, entry| entry.expires_at > now);
            if map.len() >= MAX_LIMITER_ENTRIES {
                let evict_count = (MAX_LIMITER_ENTRIES / 10).max(1);
                let mut candidates: Vec<(Instant, String)> =
                    map.iter().map(|(k, v)| (v.expires_at, k.clone())).collect();
                if evict_count < candidates.len() {
                    candidates.select_nth_unstable_by_key(evict_count - 1, |item| item.0);
                }
                for (_, k) in candidates.into_iter().take(evict_count) {
                    map.remove(&k);
                }
            }
        }
        map.insert(
            key,
            RateEntry {
                hits: vec![now],
                expires_at: now + window,
            },
        );
        false
    }

    pub fn set_typing(&self, chat_id: String, user_id: String, typing: bool) {
        let now = Instant::now();
        let mut state = self
            .typing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if typing {
            state.insert((chat_id.clone(), user_id.clone()), now);
        } else {
            state.remove(&(chat_id, user_id));
        }
        state.retain(|_, at| now.duration_since(*at).as_secs() < 6);
    }

    pub fn typing_users(&self, chat_id: &str, user_id: &str) -> Vec<String> {
        let now = Instant::now();
        let mut state = self
            .typing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.retain(|_, at| now.duration_since(*at).as_secs() < 6);
        state
            .iter()
            .filter(|&((cid, uid), _)| cid == chat_id && uid != user_id)
            .map(|((_, uid), _)| uid.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn limiter_enforces_hard_cap_evicts_expired_by_window_and_hashes_long_keys() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect_lazy("sqlite::memory:")
            .unwrap();
        let state = AppState::new(pool);

        let long_a = format!("{}a", "x".repeat(10_000));
        let long_b = format!("{}b", "x".repeat(10_000));
        assert!(!state.rate_limited(long_a, 1, 60));
        assert!(!state.rate_limited(long_b, 1, 60));
        {
            let map = state.limiter.lock().unwrap();
            assert!(map.keys().all(|k| k.len() <= 256));
        }

        assert!(!state.rate_limited("short-win", 1, 1));
        std::thread::sleep(std::time::Duration::from_millis(1100));

        for i in 0..55_000 {
            let _ = state.rate_limited(format!("bulk:{i}"), 1, 60);
        }

        let map = state.limiter.lock().unwrap();
        assert!(
            map.len() <= 50_000,
            "limiter map grew unboundedly to {} entries",
            map.len()
        );
        assert!(
            !map.contains_key("short-win"),
            "expired 1-second window entry should be evicted"
        );
    }
}
