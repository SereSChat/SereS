use sqlx::SqlitePool;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    limiter: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
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
        if std::env::var("SERES_DISABLE_RATE_LIMIT").as_deref() == Ok("1") {
            return false;
        }
        let now = Instant::now();
        let mut map = self
            .limiter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let hits = map.entry(key.into()).or_default();
        hits.retain(|at| now.duration_since(*at).as_secs() < window_secs);
        if hits.len() >= limit {
            return true;
        }
        hits.push(now);
        if map.len() > 50_000 {
            map.retain(|_, values| {
                values
                    .last()
                    .is_some_and(|at| now.duration_since(*at).as_secs() < 3600)
            });
        }
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
