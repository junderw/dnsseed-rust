mod bgp_client;
mod bloom;
mod datastore;
mod globals;
mod peer;
mod printer;
mod reader;
mod timeout_stream;

use std::env;
use std::fs::File;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

use bitcoin::blockdata::block::Block;
use bitcoin::hash_types::BlockHash;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::p2p::ServiceFlags;
//use bitcoin::util::hash::BitcoinHash;

use bgp_client::BGPClient;
use datastore::{AddressState, RegexSetting, Store, U64Setting};
use peer::Peer;
use printer::{Printer, Stat};
use rand::RngExt;
use timeout_stream::TimeoutStream;

use futures::StreamExt;
use tokio::time::sleep;

use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use globals::*;

pub static START_SHUTDOWN: AtomicBool = AtomicBool::new(false);
static SCANNING: AtomicBool = AtomicBool::new(false);

struct PeerState {
    request: Arc<(u64, BlockHash, Block)>,
    pong_nonce: u64,
    node_services: u64,
    msg: (String, bool),
    fail_reason: AddressState,
    recvd_version: bool,
    recvd_verack: bool,
    recvd_pong: bool,
    recvd_addrs: bool,
    recvd_block: bool,
}

pub fn scan_node(scan_time: Instant, node: SocketAddr, manual: bool) {
    if START_SHUTDOWN.load(Ordering::Relaxed) {
        return;
    }

    let mut rng = rand::rng();
    let peer_state = Arc::new(Mutex::new(PeerState {
        recvd_version: false,
        recvd_verack: false,
        recvd_pong: false,
        recvd_addrs: false,
        recvd_block: false,
        pong_nonce: rng.random(),
        node_services: 0,
        fail_reason: AddressState::Timeout,
        msg: (String::new(), false),
        request: Arc::clone(&REQUEST_BLOCK.lock().unwrap()),
    }));
    let final_peer_state = Arc::clone(&peer_state);

    tokio::spawn(async move {
        tokio::time::sleep_until(scan_time).await;
        PRINTER.set_stat(Stat::NewConnection);
        let timeout = DATA_STORE.get_u64(U64Setting::RunTimeout);

        let peer_result = Peer::new(
            node.clone(),
            &TOR_PROXY,
            Duration::from_secs(timeout),
            &PRINTER,
        )
        .await;

        if let Ok((write, read)) = peer_result {
            let timeout_stream = TimeoutStream::new_timeout(
                read,
                scan_time + Duration::from_secs(DATA_STORE.get_u64(U64Setting::RunTimeout)),
            );
            let mut timeout_stream = std::pin::pin!(timeout_stream);

            while let Some(msg) = timeout_stream.next().await {
                let mut state_lock = peer_state.lock().unwrap();
                macro_rules! check_set_flag {
                    ($recvd_flag: ident, $msg: expr) => {{
                        if state_lock.$recvd_flag {
                            state_lock.fail_reason = AddressState::ProtocolViolation;
                            state_lock.msg = (format!("due to dup {}", $msg), true);
                            state_lock.$recvd_flag = false;
                            break;
                        }
                        state_lock.$recvd_flag = true;
                    }};
                }
                state_lock.fail_reason = AddressState::TimeoutDuringRequest;
                match msg {
                    Some(NetworkMessage::Version(ver)) => {
                        if ver.start_height < 0
                            || ver.start_height as u64 > state_lock.request.0 + 1008 * 2
                        {
                            state_lock.fail_reason = AddressState::HighBlockCount;
                            break;
                        }
                        let safe_ua = ver
                            .user_agent
                            .replace(|c: char| !c.is_ascii() || c < ' ' || c > '~', "");
                        if (ver.start_height as u64) < state_lock.request.0 {
                            state_lock.msg = (
                                format!("({} < {})", ver.start_height, state_lock.request.0),
                                true,
                            );
                            state_lock.fail_reason = AddressState::LowBlockCount;
                            break;
                        }
                        let min_version = DATA_STORE.get_u64(U64Setting::MinProtocolVersion);
                        if (ver.version as u64) < min_version {
                            state_lock.msg = (format!("({} < {})", ver.version, min_version), true);
                            state_lock.fail_reason = AddressState::LowVersion;
                            break;
                        }
                        if !ver.services.has(ServiceFlags::NETWORK)
                            && !ver.services.has(ServiceFlags::NETWORK_LIMITED)
                        {
                            state_lock.msg =
                                (format!("({}: services {:x})", safe_ua, ver.services), true);
                            state_lock.fail_reason = AddressState::NotFullNode;
                            break;
                        }
                        if !DATA_STORE
                            .get_regex(RegexSetting::SubverRegex)
                            .is_match(&ver.user_agent)
                        {
                            state_lock.msg = (format!("subver {}", safe_ua), true);
                            state_lock.fail_reason = AddressState::BadVersion;
                            break;
                        }
                        check_set_flag!(recvd_version, "version");
                        state_lock.node_services = ver.services.to_u64();
                        state_lock.msg = (format!("(subver: {})", safe_ua), false);
                        if write.try_send(NetworkMessage::SendAddrV2).is_err() {
                            break;
                        }
                        if write.try_send(NetworkMessage::Verack).is_err() {
                            break;
                        }
                    }
                    Some(NetworkMessage::Verack) => {
                        check_set_flag!(recvd_verack, "verack");
                        if write
                            .try_send(NetworkMessage::Ping(state_lock.pong_nonce))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Some(NetworkMessage::Ping(v)) => {
                        if write.try_send(NetworkMessage::Pong(v)).is_err() {
                            break;
                        }
                    }
                    Some(NetworkMessage::Pong(v)) => {
                        if v != state_lock.pong_nonce {
                            state_lock.fail_reason = AddressState::ProtocolViolation;
                            state_lock.msg = ("due to invalid pong nonce".to_string(), true);
                            break;
                        }
                        check_set_flag!(recvd_pong, "pong");
                        if write.try_send(NetworkMessage::GetAddr).is_err() {
                            break;
                        }
                    }
                    Some(NetworkMessage::Addr(addrs)) => {
                        if addrs.len() > 1000 {
                            state_lock.fail_reason = AddressState::ProtocolViolation;
                            state_lock.msg =
                                (format!("due to oversized addr: {}", addrs.len()), true);
                            state_lock.recvd_addrs = false;
                            break;
                        }
                        if addrs.len() > 10 {
                            if !state_lock.recvd_addrs {
                                if write
                                    .try_send(NetworkMessage::GetData(vec![
                                        Inventory::WitnessBlock(state_lock.request.1),
                                    ]))
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            state_lock.recvd_addrs = true;
                        }
                        DATA_STORE.add_fresh_nodes(&addrs);
                    }
                    Some(NetworkMessage::AddrV2(addrs)) => {
                        if addrs.len() > 1000 {
                            state_lock.fail_reason = AddressState::ProtocolViolation;
                            state_lock.msg =
                                (format!("due to oversized addr: {}", addrs.len()), true);
                            state_lock.recvd_addrs = false;
                            break;
                        }
                        if addrs.len() > 10 {
                            if !state_lock.recvd_addrs {
                                if write
                                    .try_send(NetworkMessage::GetData(vec![
                                        Inventory::WitnessBlock(state_lock.request.1),
                                    ]))
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            state_lock.recvd_addrs = true;
                        }
                        DATA_STORE.add_fresh_nodes_v2(&addrs);
                    }
                    Some(NetworkMessage::Block(block)) => {
                        if block != state_lock.request.2 {
                            state_lock.fail_reason = AddressState::ProtocolViolation;
                            state_lock.msg = ("due to bad block".to_string(), true);
                            break;
                        }
                        check_set_flag!(recvd_block, "block");
                        break;
                    }
                    Some(NetworkMessage::Inv(invs)) => {
                        for inv in invs {
                            match inv {
                                Inventory::Transaction(_) | Inventory::WitnessTransaction(_) => {
                                    state_lock.fail_reason = AddressState::EvilNode;
                                    state_lock.msg =
                                        ("due to unrequested inv tx".to_string(), true);
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                    Some(NetworkMessage::Tx(_)) => {
                        state_lock.fail_reason = AddressState::EvilNode;
                        state_lock.msg = ("due to unrequested transaction".to_string(), true);
                        break;
                    }
                    Some(NetworkMessage::Unknown { command, .. }) => {
                        if command.as_ref() == "gnop" {
                            state_lock.msg = (format!("(bad msg type {})", command), true);
                            state_lock.fail_reason = AddressState::EvilNode;
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Final state handling
        PRINTER.set_stat(Stat::ConnectionClosed);

        let mut state_lock = final_peer_state.lock().unwrap();
        if state_lock.recvd_version
            && state_lock.recvd_verack
            && state_lock.recvd_pong
            && state_lock.recvd_addrs
            && state_lock.recvd_block
        {
            let old_state =
                DATA_STORE.set_node_state(node, AddressState::Good, state_lock.node_services);
            if manual || (old_state != AddressState::Good && state_lock.msg.0 != "") {
                PRINTER.add_line(
                    format!(
                        "Updating {} from {} to Good {}",
                        node,
                        old_state.to_str(),
                        &state_lock.msg.0
                    ),
                    state_lock.msg.1,
                );
            }
        } else {
            assert!(state_lock.fail_reason != AddressState::Good);
            if state_lock.fail_reason == AddressState::TimeoutDuringRequest
                && state_lock.recvd_version
                && state_lock.recvd_verack
            {
                if !state_lock.recvd_pong {
                    state_lock.fail_reason = AddressState::TimeoutAwaitingPong;
                } else if !state_lock.recvd_addrs {
                    state_lock.fail_reason = AddressState::TimeoutAwaitingAddr;
                } else if !state_lock.recvd_block {
                    state_lock.fail_reason = AddressState::TimeoutAwaitingBlock;
                }
            }
            let old_state = DATA_STORE.set_node_state(node, state_lock.fail_reason, 0);
            if (manual || old_state != state_lock.fail_reason)
                && state_lock.fail_reason == AddressState::TimeoutDuringRequest
            {
                PRINTER.add_line(
                    format!(
                        "Updating {} from {} to Timeout During Request (ver: {}, vack: {})",
                        node,
                        old_state.to_str(),
                        state_lock.recvd_version,
                        state_lock.recvd_verack
                    ),
                    true,
                );
            } else if manual
                || (old_state != state_lock.fail_reason
                    && state_lock.msg.0 != ""
                    && state_lock.msg.1)
            {
                PRINTER.add_line(
                    format!(
                        "Updating {} from {} to {} {}",
                        node,
                        old_state.to_str(),
                        state_lock.fail_reason.to_str(),
                        &state_lock.msg.0
                    ),
                    state_lock.msg.1,
                );
            }
        }
    });
}

fn poll_dnsseeds(bgp_client: Arc<BGPClient>) {
    tokio::spawn(async move {
        let mut new_addrs = 0;
        for seed in [
            "seed.bitcoin.sipa.be",
            "dnsseed.bitcoin.dashjr.org",
            "seed.bitcoinstats.com",
            "seed.bitcoin.jonasschnelli.ch",
            "seed.btc.petertodd.org",
            "seed.bitcoin.sprovoost.nl",
            "dnsseed.emzy.de",
        ]
        .iter()
        {
            new_addrs += DATA_STORE.add_fresh_addrs(
                (*seed, 8333u16)
                    .to_socket_addrs()
                    .unwrap_or(Vec::new().into_iter()),
            );
            new_addrs += DATA_STORE.add_fresh_addrs(
                (("x9.".to_string() + seed).as_str(), 8333u16)
                    .to_socket_addrs()
                    .unwrap_or(Vec::new().into_iter()),
            );
        }
        PRINTER.add_line(
            format!("Added {} new addresses from other DNS seeds", new_addrs),
            false,
        );

        sleep(Duration::from_secs(60)).await;

        let bgp_clone = Arc::clone(&bgp_client);
        let _ = tokio::join!(DATA_STORE.save_data(), DATA_STORE.write_dns(bgp_clone));

        if !START_SHUTDOWN.load(Ordering::Relaxed) {
            poll_dnsseeds(bgp_client);
        } else {
            bgp_client.disconnect();
        }
    });
}

fn scan_net() {
    tokio::spawn(async {
        let start_time = Instant::now();
        let mut scan_nodes = DATA_STORE.get_next_scan_nodes();
        PRINTER.add_line(format!("Got {} addresses to scan", scan_nodes.len()), false);
        if !scan_nodes.is_empty() {
            let per_iter_time = Duration::from_millis(
                datastore::SECS_PER_SCAN_RESULTS * 1000 / scan_nodes.len() as u64,
            );
            let mut iter_time = start_time;

            for node in scan_nodes.drain(..) {
                scan_node(iter_time, node, false);
                iter_time += per_iter_time;
            }
        }
        tokio::time::sleep_until(
            start_time + Duration::from_secs(datastore::SECS_PER_SCAN_RESULTS),
        )
        .await;
        if !START_SHUTDOWN.load(Ordering::Relaxed) {
            scan_net();
        }
    });
}

fn make_trusted_conn(trusted_sockaddr: SocketAddr, bgp_client: Arc<BGPClient>) {
    let bgp_reload = Arc::clone(&bgp_client);
    tokio::spawn(async move {
        let peer_result = Peer::new(
            trusted_sockaddr.clone(),
            &TOR_PROXY,
            Duration::from_secs(600),
            &PRINTER,
        )
        .await;

        if let Ok((trusted_write, trusted_read)) = peer_result {
            PRINTER.add_line("Connected to local peer".to_string(), false);
            let mut starting_height = 0i32;
            let timeout_stream =
                TimeoutStream::new_persistent(trusted_read, Duration::from_secs(600));
            let mut timeout_stream = std::pin::pin!(timeout_stream);

            while let Some(msg) = timeout_stream.next().await {
                if START_SHUTDOWN.load(Ordering::Relaxed) {
                    break;
                }
                match msg {
                    Some(NetworkMessage::Version(ver)) => {
                        if trusted_write.try_send(NetworkMessage::Verack).is_err() {
                            break;
                        }
                        starting_height = ver.start_height;
                    }
                    Some(NetworkMessage::Verack) => {
                        if trusted_write.try_send(NetworkMessage::SendHeaders).is_err() {
                            break;
                        }
                        if trusted_write
                            .try_send(NetworkMessage::GetHeaders(GetHeadersMessage {
                                version: 70015,
                                locator_hashes: vec![HIGHEST_HEADER.lock().unwrap().0.clone()],
                                stop_hash: BlockHash::all_zeros(),
                            }))
                            .is_err()
                        {
                            break;
                        }
                        if trusted_write.try_send(NetworkMessage::GetAddr).is_err() {
                            break;
                        }
                    }
                    Some(NetworkMessage::Addr(addrs)) => {
                        DATA_STORE.add_fresh_nodes(&addrs);
                    }
                    Some(NetworkMessage::Headers(headers)) => {
                        if headers.is_empty() {
                            continue;
                        }
                        let mut header_map = HEADER_MAP.lock().unwrap();
                        let mut height_map = HEIGHT_MAP.lock().unwrap();

                        if let Some(height) = header_map.get(&headers[0].prev_blockhash).cloned() {
                            let mut should_break = false;
                            for i in 0..headers.len() {
                                let hash = headers[i].block_hash();
                                if i < headers.len() - 1 && headers[i + 1].prev_blockhash != hash {
                                    should_break = true;
                                    break;
                                }
                                header_map.insert(headers[i].block_hash(), height + 1 + (i as u64));
                                height_map.insert(height + 1 + (i as u64), headers[i].block_hash());
                            }
                            if should_break {
                                break;
                            }

                            let top_height = height + headers.len() as u64;
                            *HIGHEST_HEADER.lock().unwrap() =
                                (headers.last().unwrap().block_hash(), top_height);
                            PRINTER.set_stat(printer::Stat::HeaderCount(top_height));

                            if top_height >= starting_height as u64 {
                                if trusted_write
                                    .try_send(NetworkMessage::GetData(vec![
                                        Inventory::WitnessBlock(
                                            height_map.get(&(top_height - 216)).unwrap().clone(),
                                        ),
                                    ]))
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        } else {
                            // Wat? Lets start again...
                            PRINTER.add_line(
                                "Got unconnected headers message from local trusted peer"
                                    .to_string(),
                                true,
                            );
                        }
                        // Drop the locks before calling try_send
                        drop(header_map);
                        drop(height_map);
                        if trusted_write
                            .try_send(NetworkMessage::GetHeaders(GetHeadersMessage {
                                version: 70015,
                                locator_hashes: vec![HIGHEST_HEADER.lock().unwrap().0.clone()],
                                stop_hash: BlockHash::all_zeros(),
                            }))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Some(NetworkMessage::Block(block)) => {
                        let hash = block.block_hash();
                        let header_map = HEADER_MAP.lock().unwrap();
                        let height = *header_map
                            .get(&hash)
                            .expect("Got loose block from trusted peer we coulnd't have requested");
                        if height == HIGHEST_HEADER.lock().unwrap().1 - 216 {
                            *REQUEST_BLOCK.lock().unwrap() = Arc::new((height, hash, block));
                            if !SCANNING.swap(true, Ordering::SeqCst) {
                                scan_net();
                                poll_dnsseeds(Arc::clone(&bgp_client));
                            }
                        }
                    }
                    Some(NetworkMessage::Ping(v)) => {
                        if trusted_write.try_send(NetworkMessage::Pong(v)).is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Reconnect if not shutting down
        if !START_SHUTDOWN.load(Ordering::Relaxed) {
            PRINTER.add_line("Lost connection from trusted peer".to_string(), true);
            make_trusted_conn(trusted_sockaddr, bgp_reload);
        }
    });
}

fn parse_bgp_identifier(s: &str) -> Result<u32, String> {
    // Try hex format (0x...)
    if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u32::from_str_radix(hex_str, 16)
            .map_err(|e| format!("Invalid hex identifier: {}", e));
    }
    // Try IPv4 format (a.b.c.d)
    if s.contains('.') {
        let mut octets = [0u8; 4];
        let mut count = 0;
        for (i, p) in s.split('.').enumerate() {
            if i >= 4 {
                return Err(format!("Invalid IPv4 identifier: {}", s));
            }
            match p.parse::<u8>() {
                Ok(v) => octets[i] = v,
                Err(_) => return Err(format!("Invalid IPv4 identifier: {}", s)),
            }
            count = i + 1;
        }
        if count == 4 {
            return Ok(u32::from_be_bytes(octets));
        }
        return Err(format!("Invalid IPv4 identifier: {}", s));
    }
    // Try decimal format
    s.parse::<u32>()
        .map_err(|e| format!("Invalid decimal identifier: {}", e))
}

fn main() {
    // Initialize tracing subscriber with env filter
    // Use RUST_LOG env var to control log levels, e.g. RUST_LOG=debug or RUST_LOG=dnsseed_rust::bgp_client=trace
    // Use RUST_LOG_FILE env var to write logs to a file (e.g. RUST_LOG_FILE=/tmp/dnsseed.log)
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let log_file_path =
        env::var("RUST_LOG_FILE").unwrap_or_else(|_| format!("dnsseed-{}.log", std::process::id()));
    // Write to file (wrapped in Mutex for thread-safety)
    let file = File::create(&log_file_path)
        .expect(&format!("Failed to create log file: {}", log_file_path));
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_writer(Mutex::new(file))
                .with_ansi(false)
                .with_target(true)
                .with_thread_ids(true),
        )
        .with(filter)
        .init();
    eprintln!("Logging to file: {}", log_file_path);

    info!("Starting dnsseed-rust");

    let argc = env::args().len();
    if !(6..=7).contains(&argc) {
        println!("USAGE: dnsseed-rust datastore localPeerAddress tor_proxy_addr bgp_peer bgp_peer_asn [bgp_identifier]");
        println!(
            "  bgp_identifier can be: decimal (12345), hex (0x453b1215), or IPv4 (69.59.18.21)"
        );
        println!("  Default bgp_identifier: 0x453b1215 (69.59.18.21)");
        return;
    }

    // Parse arguments before entering async runtime
    let mut args = env::args();
    args.next();
    let path = args.next().unwrap();
    let trusted_sockaddr: SocketAddr = args.next().unwrap().parse().unwrap();
    let tor_socks5_sockaddr: SocketAddr = args.next().unwrap().parse().unwrap();
    assert!(
        TOR_PROXY.set(tor_socks5_sockaddr).is_ok(),
        "TOR_PROXY already set"
    );
    let bgp_sockaddr: SocketAddr = args.next().unwrap().parse().unwrap();
    let bgp_peerasn: u32 = args.next().unwrap().parse().unwrap();
    let bgp_identifier: u32 = args.next().map_or(0x453b1215, |s| {
        parse_bgp_identifier(&s).unwrap_or(0x453b1215)
    });

    info!(
        path = %path,
        trusted_peer = %trusted_sockaddr,
        tor_proxy = %tor_socks5_sockaddr,
        bgp_peer = %bgp_sockaddr,
        bgp_asn = bgp_peerasn,
        bgp_identifier = format_args!("0x{:08x}", bgp_identifier),
        "Parsed configuration"
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_cpus::get().max(1) + 1)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async move {
        let store = Store::new(path).await.expect("Failed to initialize store");
        assert!(DATA_STORE.set(store).is_ok(), "DATA_STORE already set");
        assert!(
            PRINTER.set(Printer::new(&DATA_STORE)).is_ok(),
            "PRINTER already set"
        );

        let bgp_client = BGPClient::new(
            bgp_peerasn,
            bgp_sockaddr,
            Duration::from_secs(300),
            &PRINTER,
            bgp_identifier,
        );
        make_trusted_conn(trusted_sockaddr, Arc::clone(&bgp_client));

        reader::read(&DATA_STORE, &PRINTER, bgp_client);

        // Keep the runtime alive - the spawned tasks will run
        // The runtime will shutdown when START_SHUTDOWN is set and tasks complete
        loop {
            sleep(Duration::from_secs(1)).await;
            if START_SHUTDOWN.load(Ordering::Relaxed) {
                // Allow some time for cleanup
                sleep(Duration::from_secs(2)).await;
                break;
            }
        }
    });

    // Final save on shutdown
    rt.block_on(async {
        DATA_STORE.save_data().await;
    });
}
