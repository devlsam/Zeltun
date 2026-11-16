use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;

pub type SharedDnsResp = Option<Vec<u8>>;
type CacheMap = Arc<Mutex<(u64, HashMap<Vec<u8>, (Vec<u8>, Instant)>)>>;
type InflightMap = Arc<Mutex<HashMap<(u64, Vec<u8>), watch::Receiver<SharedDnsResp>>>>;

pub struct InflightGuard {
    map: InflightMap,
    key: (u64, Vec<u8>),
    pub tx: watch::Sender<SharedDnsResp>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.map.lock().unwrap().remove(&self.key);
    }
}

pub enum InflightSlot {
    Leader(InflightGuard),
    Waiter(watch::Receiver<SharedDnsResp>),
}

/// Copies the caller's 2-byte DNS transaction ID onto a response packet.
pub fn patch_txid(mut pkt: Vec<u8>, query: &[u8]) -> Vec<u8> {
    if pkt.len() >= 2 && query.len() >= 2 {
        pkt[0] = query[0];
        pkt[1] = query[1];
    }
    pkt
}

/// Shared DNS response cache and per-query in-flight coalescing registry.
#[derive(Clone)]
pub struct DnsCacheStore {
    cache: CacheMap,
    inflight: InflightMap,
}

impl DnsCacheStore {
    pub fn new(epoch: u64) -> Self {
        Self {
            cache: Arc::new(Mutex::new((epoch, HashMap::new()))),
            inflight: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn lookup(&self, q_key: &[u8], cur_epoch: u64, query: &[u8]) -> Option<Vec<u8>> {
        let mut guard = self.cache.lock().unwrap();
        if guard.0 != cur_epoch {
            guard.1.clear();
            guard.0 = cur_epoch;
        }
        let (cached, expires_at) = guard.1.get(q_key)?;
        if Instant::now() < *expires_at {
            return Some(patch_txid(cached.clone(), query));
        }
        guard.1.remove(q_key);
        None
    }

    pub fn store(&self, q_key: Vec<u8>, cur_epoch: u64, resp: &[u8]) {
        if resp.len() < 12 {
            return;
        }
        let ttl_secs = match resp[3] & 0x0f {
            0 => 60, // NOERROR
            3 => 15, // NXDOMAIN
            _ => return, // Never cache SERVFAIL, REFUSED, FORMERR, etc.
        };
        let mut guard = self.cache.lock().unwrap();
        if guard.0 == cur_epoch {
            if guard.1.len() > 1000 {
                guard.1.clear();
            }
            guard.1.insert(q_key, (resp.to_vec(), Instant::now() + Duration::from_secs(ttl_secs)));
        }
    }

    pub fn acquire_inflight(&self, cur_epoch: u64, q_key: &[u8]) -> InflightSlot {
        let mut map = self.inflight.lock().unwrap();
        let key = (cur_epoch, q_key.to_vec());
        if let Some(rx) = map.get(&key) {
            return InflightSlot::Waiter(rx.clone());
        }
        let (tx, rx) = watch::channel(None);
        map.insert(key.clone(), rx);
        InflightSlot::Leader(InflightGuard { map: self.inflight.clone(), key, tx })
    }
}

