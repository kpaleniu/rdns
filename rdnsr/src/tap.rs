//! What `rdnsr` writes to dnstap, and which of it (`TODO.md` #191).
//!
//! The writer is `rdns_transport::dnstap`, shared with `rdnsd`; this is the
//! choosing. BIND's `dnstap` takes the types by name and Unbound has a switch
//! per direction; here `--dnstap-types` takes BIND's names, each meaning both
//! directions, and defaults to `client`.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use anyhow::bail;
use rdns::dnstap::{Entry, MessageType, SocketProtocol, Timestamp};
use rdns::resolver::ExchangeTap;
use rdns_transport::dnstap::Sink;

/// Which exchanges go to the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Types {
    pub(crate) client: bool,
    pub(crate) resolver: bool,
    pub(crate) forwarder: bool,
}

/// `--dnstap-types`, refused for a name it does not know and for any name at
/// all without `--dnstap` (`CLAUDE.md` §15).
pub(crate) fn types(names: &[String], dnstap: bool) -> anyhow::Result<Types> {
    if !names.is_empty() && !dnstap {
        bail!("--dnstap-types chooses what --dnstap writes, and there is no --dnstap");
    }
    if names.is_empty() {
        return Ok(Types {
            client: true,
            resolver: false,
            forwarder: false,
        });
    }
    let mut types = Types {
        client: false,
        resolver: false,
        forwarder: false,
    };
    for name in names.iter().flat_map(|n| n.split(',')).map(str::trim) {
        match name {
            "client" => types.client = true,
            "resolver" => types.resolver = true,
            "forwarder" => types.forwarder = true,
            other => {
                bail!("--dnstap-types {other:?}: the types are client, resolver and forwarder")
            }
        }
    }
    Ok(types)
}

/// The resolver's tap, writing to the sink once there is one: the resolver is
/// built before the dry run returns, and the sink opens a connection, which a
/// dry run must not (`CLAUDE.md` §15).
pub(crate) fn exchange_tap(slot: Arc<OnceLock<Sink>>, types: Types) -> ExchangeTap {
    Arc::new(move |entry: &Entry<'_>| {
        let wanted = match entry.message_type {
            MessageType::ResolverQuery | MessageType::ResolverResponse => types.resolver,
            MessageType::ForwarderQuery | MessageType::ForwarderResponse => types.forwarder,
            _ => false,
        };
        if !wanted {
            return;
        }
        if let Some(sink) = slot.get() {
            sink.record(&Entry {
                identity: sink.identity(),
                version: sink.version(),
                ..entry.clone()
            });
        }
    })
}

/// One client exchange: `CLIENT_QUERY` as it arrived, and `CLIENT_RESPONSE`
/// when one went back.
pub(crate) fn record_client(
    sink: &Sink,
    protocol: SocketProtocol,
    peer: SocketAddr,
    arrived: Timestamp,
    query: &[u8],
    reply: Option<&[u8]>,
) {
    let entry = Entry {
        identity: sink.identity(),
        version: sink.version(),
        message_type: MessageType::ClientQuery,
        socket_protocol: Some(protocol),
        initiator: Some(peer),
        responder: None,
        query_time: arrived,
        response_time: None,
        query: Some(query),
        response: None,
        zone: None,
    };
    sink.record(&entry);
    if let Some(reply) = reply {
        sink.record(&Entry {
            message_type: MessageType::ClientResponse,
            response_time: Some(Timestamp::now()),
            query: None,
            response: Some(reply),
            ..entry
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_types_and_their_refusals() {
        let names = |n: &[&str]| n.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            types(&[], true).unwrap(),
            Types {
                client: true,
                resolver: false,
                forwarder: false
            },
            "client by default"
        );
        let both = types(&names(&["client,resolver"]), true).unwrap();
        assert!(both.client && both.resolver && !both.forwarder);
        assert!(types(&names(&["bogus"]), true)
            .unwrap_err()
            .to_string()
            .contains("bogus"));
        assert!(types(&names(&["client"]), false)
            .unwrap_err()
            .to_string()
            .contains("--dnstap"));
    }
}

#[cfg(test)]
mod capture {
    use std::sync::Arc;
    use std::time::Duration;

    use rdns::dnstap::read;
    use rdns::rpz::PolicyZones;
    use rdns::shutdown::Shutdown;
    use rdns::{DnsMessage, OpCode};
    use rdns_transport::dnstap::{Sink, Target};
    use tokio::net::UdpSocket;

    use crate::serve::udp_main;
    use crate::testutil::*;

    /// One `CLIENT_QUERY` and one `CLIENT_RESPONSE` per client query, read back
    /// out of a capture file. The UPDATE is NOTIMP out of the message alone.
    /// Fails with `record_client` removed from the UDP loop: no data frames
    /// between START and STOP.
    #[tokio::test]
    async fn a_client_exchange_is_two_frames() {
        let dir = ScratchDir::new("rdnsr-dnstap");
        let path = dir.join("capture.fstrm");
        let shutdown = Shutdown::new();
        let ctx = test_shell();
        let sink = Sink::spawn(
            &Target::File(path.clone()),
            0,
            b"test".to_vec(),
            b"rdnsr".to_vec(),
            (*ctx.metrics).clone(),
            shutdown.stop_handle(),
        )
        .await
        .expect("the capture opens");
        let serving = serving(test_resolver(), ctx, PolicyZones::default());
        let mut serving = Arc::into_inner(serving).expect("not shared yet");
        serving.dnstap = Some(sink);
        let serving = Arc::new(serving);

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let addr = socket.local_addr().expect("addr");
        let server = tokio::spawn(udp_main(
            socket,
            serving,
            16,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind a client");
        let query = message(OpCode::Update, false);
        client.send_to(&query, addr).await.expect("send");
        let mut buf = vec![0u8; 512];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
            .await
            .expect("a reply in time")
            .expect("a reply");
        DnsMessage::try_from_bytes(&buf[..n]).expect("parses");

        shutdown.begin();
        let _ = server.await;
        let bytes = rdns::test_util::closed_capture(&path, Duration::from_secs(10))
            .await
            .expect("the capture closed");
        let messages: Vec<_> = read::data_frames(&bytes)
            .into_iter()
            .map(|frame| read::message(frame).expect("decodes"))
            .collect();
        assert_eq!(
            messages.iter().map(|m| m.message_type).collect::<Vec<_>>(),
            vec![5, 6],
            "CLIENT_QUERY, CLIENT_RESPONSE"
        );
        assert_eq!(messages[0].query.as_deref(), Some(&query[..]));
        assert_eq!(messages[0].initiator.as_deref(), Some(&[127, 0, 0, 1][..]));
        assert_eq!(messages[1].response.as_deref(), Some(&buf[..n]));
    }
}
