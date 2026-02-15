use std::cmp;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::consensus::encode;
use bitcoin::consensus::encode::{Decodable, Encodable};
use bitcoin::io::FromStd;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};

use bytes::Buf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tokio_util::codec::{Decoder, Encoder, Framed};

use futures::{SinkExt, Stream, StreamExt};

use tracing::{debug, error, trace, warn};

use crate::printer::Printer;

#[derive(Debug)]
pub enum CodecError {
    Encode(encode::Error),
    Io(io::Error),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::Encode(e) => write!(f, "Encode error: {}", e),
            CodecError::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for CodecError {}

impl From<io::Error> for CodecError {
    fn from(e: io::Error) -> Self {
        CodecError::Io(e)
    }
}

impl From<encode::Error> for CodecError {
    fn from(e: encode::Error) -> Self {
        CodecError::Encode(e)
    }
}

struct BytesCoder<'a>(&'a mut bytes::BytesMut);
impl<'a> std::io::Write for BytesCoder<'a> {
    fn write(&mut self, b: &[u8]) -> Result<usize, std::io::Error> {
        self.0.extend_from_slice(&b);
        Ok(b.len())
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}
struct BytesDecoder<'a> {
    buf: &'a mut bytes::BytesMut,
    pos: usize,
}
impl<'a> std::io::Read for BytesDecoder<'a> {
    fn read(&mut self, b: &mut [u8]) -> Result<usize, std::io::Error> {
        let copy_len = cmp::min(b.len(), self.buf.len() - self.pos);
        b[..copy_len].copy_from_slice(&self.buf[self.pos..self.pos + copy_len]);
        self.pos += copy_len;
        Ok(copy_len)
    }
}

struct MsgCoder<'a>(&'a Printer);
impl Decoder for MsgCoder<'_> {
    type Item = Option<NetworkMessage>;
    type Error = CodecError;

    fn decode(
        &mut self,
        bytes: &mut bytes::BytesMut,
    ) -> Result<Option<Option<NetworkMessage>>, CodecError> {
        let mut decoder = BytesDecoder { buf: bytes, pos: 0 };
        match RawNetworkMessage::consensus_decode(FromStd::new_mut(&mut decoder)) {
            Ok(res) => {
                decoder.buf.advance(decoder.pos);
                if *res.magic() == Magic::BITCOIN {
                    trace!(command = ?res.payload().cmd(), "Decoded Bitcoin message");
                    Ok(Some(Some(res.into_payload())))
                } else {
                    warn!(
                        expected = ?res.magic(),
                        actual = ?Magic::BITCOIN,
                        "Unexpected network magic"
                    );
                    Err(encode::Error::ParseFailed("Unexpected network magic").into())
                }
            }
            Err(e) => match e {
                encode::Error::Io(_) => Ok(None),
                _ => {
                    error!(error = ?e, "Error decoding Bitcoin message");
                    self.0
                        .add_line(format!("Error decoding message: {:?}", e), true);
                    Err(e.into())
                }
            },
        }
    }
}
impl Encoder<NetworkMessage> for MsgCoder<'_> {
    type Error = std::io::Error;

    fn encode(
        &mut self,
        msg: NetworkMessage,
        res: &mut bytes::BytesMut,
    ) -> Result<(), std::io::Error> {
        if let Err(_) = RawNetworkMessage::new(Magic::BITCOIN, msg)
            .consensus_encode(FromStd::new_mut(&mut BytesCoder(res)))
        {
            //XXX
        }
        Ok(())
    }
}

// base32 encoder and tests stolen (transliterated) from Bitcoin Core
// Copyright (c) 2012-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see
// http://www.opensource.org/licenses/mit-license.php.
fn encode_base32(inp: &[u8]) -> String {
    let mut ret = String::with_capacity(((inp.len() + 4) / 5) * 8);

    let alphabet = "abcdefghijklmnopqrstuvwxyz234567";
    let mut acc: u16 = 0;
    let mut bits: u8 = 0;
    for i in inp {
        acc = ((acc << 8) | *i as u16) & ((1 << (8 + 5 - 1)) - 1);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((acc >> bits) & ((1 << 5) - 1)) as usize;
            ret += &alphabet[idx..idx + 1];
        }
    }
    if bits != 0 {
        let idx = ((acc << (5 - bits)) & ((1 << 5) - 1)) as usize;
        ret += &alphabet[idx..idx + 1];
    }
    while ret.len() % 8 != 0 {
        ret += "="
    }
    return ret;
}

#[test]
fn test_encode_base32() {
    let tests_in = ["", "f", "fo", "foo", "foob", "fooba", "foobar"];
    let tests_out = [
        "",
        "my======",
        "mzxq====",
        "mzxw6===",
        "mzxw6yq=",
        "mzxw6ytb",
        "mzxw6ytboi======",
    ];
    for (inp, out) in tests_in.iter().zip(tests_out.iter()) {
        assert_eq!(&encode_base32(inp.as_bytes()), out);
    }
    // My seednode's onion addr:
    assert_eq!(
        &encode_base32(&[0x6a, 0x8b, 0xd2, 0x78, 0x3f, 0x7a, 0xf8, 0x92, 0x8f, 0x80]),
        "nkf5e6b7pl4jfd4a"
    );
}

async fn connect_via_tor(
    addr: SocketAddr,
    v6addr: std::net::Ipv6Addr,
    tor_proxy: SocketAddr,
    connect_timeout: Duration,
) -> io::Result<TcpStream> {
    debug!(peer = %addr, proxy = %tor_proxy, "Connecting via Tor proxy");

    let mut stream = timeout(connect_timeout, TcpStream::connect(tor_proxy))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "timeout reached"))??;

    trace!(peer = %addr, "Tor proxy connected, sending SOCKS5 auth");
    stream.write_all(&[5u8, 1u8, 0u8]).await?; // SOCKS5 with 1 method and no auth

    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;

    if response != [5, 0] {
        warn!(peer = %addr, response = ?response, "SOCKS5 authentication failed");
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Failed to authenticate",
        ));
    }

    let hostname = encode_base32(&v6addr.octets()[6..]) + ".onion";
    trace!(peer = %addr, hostname = %hostname, "SOCKS5 auth successful, connecting to onion");

    let mut connect_msg = Vec::with_capacity(7 + hostname.len());
    connect_msg.extend_from_slice(&[5u8, 1u8, 0u8, 3u8, hostname.len() as u8]);
    connect_msg.extend_from_slice(hostname.as_bytes());
    connect_msg.push((addr.port() >> 8) as u8);
    connect_msg.push((addr.port() >> 0) as u8);
    stream.write_all(&connect_msg).await?;

    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await?;

    if response[..3] != [5, 0, 0] {
        warn!(peer = %addr, response = ?response, "SOCKS5 connect failed");
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Failed to connect",
        ));
    }

    trace!(peer = %addr, "SOCKS5 connect successful");

    // Read the address bytes
    if response[3] == 1 {
        let mut buf = [0u8; 6];
        stream.read_exact(&mut buf).await?;
    } else if response[3] == 4 {
        let mut buf = [0u8; 18];
        stream.read_exact(&mut buf).await?;
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Bogus proxy address value",
        ));
    }

    Ok(stream)
}

pub struct Peer {}
impl Peer {
    pub async fn new(
        addr: SocketAddr,
        tor_proxy: &SocketAddr,
        connect_timeout: Duration,
        printer: &'static Printer,
    ) -> Result<
        (
            mpsc::Sender<NetworkMessage>,
            impl Stream<Item = Option<NetworkMessage>>,
        ),
        (),
    > {
        debug!(peer = %addr, timeout_secs = connect_timeout.as_secs(), "Connecting to peer");

        let stream = match addr.ip() {
            IpAddr::V6(v6addr)
                if v6addr.octets()[..6] == [0xFD, 0x87, 0xD8, 0x7E, 0xEB, 0x43][..] =>
            {
                match connect_via_tor(addr, v6addr, *tor_proxy, connect_timeout).await {
                    Ok(s) => s,
                    Err(_) => {
                        debug!(peer = %addr, "Tor connection failed, scheduling retry delay");
                        sleep(connect_timeout / 10).await;
                        return Err(());
                    }
                }
            }
            _ => {
                trace!(peer = %addr, "Connecting directly (no Tor)");
                match timeout(connect_timeout, TcpStream::connect(addr)).await {
                    Ok(Ok(s)) => s,
                    _ => {
                        debug!(peer = %addr, "Connection failed, scheduling retry delay");
                        sleep(connect_timeout / 10).await;
                        return Err(());
                    }
                }
            }
        };

        debug!(peer = %addr, "TCP connection established, sending version");
        let (mut write, read) = Framed::new(stream, MsgCoder(printer)).split();
        let (sender, mut receiver) = mpsc::channel::<NetworkMessage>(10);

        // Spawn task to forward messages from channel to stream
        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                if write.send(msg).await.is_err() {
                    break;
                }
            }
        });

        let sender_clone = sender.clone();
        let _ = sender_clone
            .send(NetworkMessage::Version(VersionMessage {
                version: 70015,
                services: ServiceFlags::WITNESS,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time > 1970")
                    .as_secs() as i64,
                receiver: Address::new(&addr, ServiceFlags::NONE),
                sender: Address::new(&"0.0.0.0:0".parse().unwrap(), ServiceFlags::WITNESS),
                nonce: 0xdeadbeef,
                user_agent: "/rust-bitcoin:0.18/bluematt-tokio-client:0.1/".to_string(),
                start_height: 0,
                relay: false,
            }))
            .await;

        // Convert Result<Option<NetworkMessage>, Error> to Option<NetworkMessage>
        let read = read.map(|res| res.ok().flatten());
        Ok((sender, read))
    }
}
