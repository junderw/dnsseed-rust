use crate::{datastore::Store, printer::Printer};
use std::{
    net::SocketAddr,
    ops::Deref,
    sync::{LazyLock, OnceLock},
};

use bitcoin::{blockdata::constants::genesis_block, Block, BlockHash, Network};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Wrapper that automatically dereferences `OnceLock` to its inner value
#[derive(Copy, Clone)]
pub struct StaticRef<T> {
    inner: T,
}

impl<T> StaticRef<&'static OnceLock<T>> {
    #[inline]
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn set(&self, value: T) -> Result<(), T> {
        self.inner.set(value)
    }
}

impl<T> Deref for StaticRef<&'static OnceLock<T>> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        self.inner.get().expect("Static not initialized")
    }
}

impl<T> Deref for StaticRef<&'static LazyLock<T>> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        self.inner
    }
}

macro_rules! static_ref {
    (ONCE, $name:ident, $mod_name:ident, $type:ty) => {
        #[allow(non_snake_case)]
        mod $mod_name {
            use super::*;
            pub(super) static INNER: OnceLock<$type> = OnceLock::new();
        }

        #[allow(non_upper_case_globals)]
        pub static $name: StaticRef<&'static OnceLock<$type>> = StaticRef {
            inner: &$mod_name::INNER,
        };
    };
    (LAZY, $name:ident, $mod_name:ident, $type:ty, $init:expr) => {
        #[allow(non_snake_case)]
        mod $mod_name {
            use super::*;
            pub(super) static INNER: LazyLock<$type> = LazyLock::new($init);
        }

        #[allow(non_upper_case_globals)]
        pub static $name: StaticRef<&'static LazyLock<$type>> = StaticRef {
            inner: &$mod_name::INNER,
        };
    };
}
static_ref!(ONCE, DATA_STORE, data_store, Store);
static_ref!(ONCE, PRINTER, printer, Printer);
static_ref!(ONCE, TOR_PROXY, tor_proxy, SocketAddr);
static_ref!(
    LAZY,
    HEADER_MAP,
    header_map,
    Mutex<HashMap<BlockHash, u64>>,
    || {
        let mut map = HashMap::with_capacity(600_000);
        map.insert(genesis_block(Network::Bitcoin).block_hash(), 0);
        Mutex::new(map)
    }
);
static_ref!(
    LAZY,
    HEIGHT_MAP,
    height_map,
    Mutex<HashMap<u64, BlockHash>>,
    || {
        let mut map = HashMap::with_capacity(600_000);
        map.insert(0, genesis_block(Network::Bitcoin).block_hash());
        Mutex::new(map)
    }
);
static_ref!(
    LAZY,
    HIGHEST_HEADER,
    highest_header,
    Mutex<(BlockHash, u64)>,
    || { Mutex::new((genesis_block(Network::Bitcoin).block_hash(), 0)) }
);
static_ref!(
    LAZY,
    REQUEST_BLOCK,
    request_block,
    Mutex<Arc<(u64, BlockHash, Block)>>,
    || {
        Mutex::new(Arc::new((
            0,
            genesis_block(Network::Bitcoin).block_hash(),
            genesis_block(Network::Bitcoin),
        )))
    }
);
