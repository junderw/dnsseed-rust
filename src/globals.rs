use std::{ops::Deref, sync::{OnceLock, LazyLock}, net::SocketAddr};
use crate::{datastore::Store, printer::Printer};

use bitcoin::{Block, BlockHash, Network, blockdata::constants::genesis_block};
use std::collections::HashMap;
use std::sync::{Mutex, Arc};

/// Wrapper that automatically dereferences OnceLock to its inner value
#[derive(Copy, Clone)]
pub struct StaticRef<T> {
    inner: T,
}

impl<T> StaticRef<&'static OnceLock<T>> {
    #[inline]
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
        &**self.inner
    }
}

macro_rules! static_ref {
    (ONCE, $name:ident, $type:ty) => {
        #[allow(non_snake_case)]
        mod $name {
            use super::*;
            pub(super) static $name: OnceLock<$type> = OnceLock::new();
        }
        
        
        #[allow(non_upper_case_globals)]
        pub const $name: StaticRef<&'static OnceLock<$type>> = StaticRef { inner: &$name::$name };
    };
    (LAZY, $name:ident, $type:ty, $init:expr) => {
        #[allow(non_snake_case)]
        mod $name {
            use super::*;
            pub(super) static $name: LazyLock<$type> = LazyLock::new($init);
        }
        
        
        #[allow(non_upper_case_globals)]
        pub const $name: StaticRef<&'static LazyLock<$type>> = StaticRef { inner: &$name::$name };
    };
}
static_ref!(ONCE, DATA_STORE, Store);
static_ref!(ONCE, PRINTER, Printer);
static_ref!(ONCE, TOR_PROXY, SocketAddr);
static_ref!(LAZY, HEADER_MAP, Mutex<HashMap<BlockHash, u64>>, || {
    let mut map = HashMap::with_capacity(600000);
    map.insert(genesis_block(Network::Bitcoin).block_hash(), 0);
    Mutex::new(map)
});
static_ref!(LAZY, HEIGHT_MAP, Mutex<HashMap<u64, BlockHash>>, || {
    let mut map = HashMap::with_capacity(600000);
    map.insert(0, genesis_block(Network::Bitcoin).block_hash());
    Mutex::new(map)
});
static_ref!(LAZY, HIGHEST_HEADER, Mutex<(BlockHash, u64)>, || {
    Mutex::new((genesis_block(Network::Bitcoin).block_hash(), 0))
});
static_ref!(LAZY, REQUEST_BLOCK, Mutex<Arc<(u64, BlockHash, Block)>>, || {
    Mutex::new(Arc::new((0, genesis_block(Network::Bitcoin).block_hash(), genesis_block(Network::Bitcoin))))
});