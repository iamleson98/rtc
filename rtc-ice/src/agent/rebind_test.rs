//! A client whose NAT mapping changes mid-call, against an ICE-lite peer (an SFU).
//!
//! The client's agent is not told: its packets simply leave from another address. The lite agent
//! must follow when, and only when, an authenticated check that nominates comes from there
//! (RFC 8445 §7.3.1.3 and §7.3.1.5), the way libwebrtc nominates toward a lite peer.

use super::selection_test::*;
use super::*;
use crate::attributes::{control::AttrControlling, use_candidate::UseCandidateAttr};
use stun::attributes::*;
use stun::fingerprint::*;
use stun::integrity::*;
use stun::message::*;
use stun::textattrs::*;

const CLIENT: &str = "10.0.0.1";
const SFU: &str = "10.0.0.2";

/// A NAT in front of the client: `inside` is the address its agent knows, `outside` the one the
/// peer hears.
struct Nat {
    inside: SocketAddr,
    outside: SocketAddr,
}

impl Nat {
    fn out(&self, a: SocketAddr) -> SocketAddr {
        if a == self.inside { self.outside } else { a }
    }

    fn back(&self, a: SocketAddr) -> SocketAddr {
        if a == self.outside { self.inside } else { a }
    }
}

/// Like `forward`, with every address renamed on the way.
fn forward_through(
    from: &mut Peer,
    to: &mut Peer,
    now: Instant,
    rename: impl Fn(SocketAddr) -> SocketAddr,
) -> bool {
    let mut moved = false;
    while let Some(packet) = from.agent.poll_write() {
        moved = true;
        from.sent.push(packet.message.to_vec());
        let inbound = TaggedBytesMut {
            now,
            transport: TransportContext {
                local_addr: rename(packet.transport.peer_addr),
                peer_addr: rename(packet.transport.local_addr),
                ecn: None,
                transport_protocol: packet.transport.transport_protocol,
            },
            message: packet.message,
        };
        let _ = to.agent.handle_read(inbound);
    }
    moved
}

/// Runs the two agents for `millis` with the client behind `nat`.
fn run_behind(client: &mut Peer, sfu: &mut Peer, clock: &mut Instant, millis: u64, nat: &Nat) {
    for _ in 0..millis / 50 {
        *clock += Duration::from_millis(50);
        client.agent.handle_timeout(*clock).unwrap();
        sfu.agent.handle_timeout(*clock).unwrap();
        loop {
            let up = forward_through(client, sfu, *clock, |a| nat.out(a));
            let down = forward_through(sfu, client, *clock, |a| nat.back(a));
            client.drain_events();
            sfu.drain_events();
            if !up && !down {
                break;
            }
        }
    }
}

/// A connected client (full, controlling) and SFU (lite, controlled).
fn connected(remote_lite: bool) -> (Peer, Peer, Instant) {
    let mut clock = Instant::now();
    let mut client = Peer::new(clock, AgentConfig::default());
    let mut sfu = Peer::new(clock, lite_config(false));
    client.agent.set_remote_ice_lite(remote_lite);
    start(
        &mut client,
        &[host(CLIENT, 1000)],
        true,
        &mut sfu,
        &[host(SFU, 2000)],
        false,
        clock,
    );
    run(&mut client, &mut sfu, &mut clock, 2000);
    assert_eq!(ConnectionState::Connected, sfu.agent.state());
    (client, sfu, clock)
}

fn nat_to(port: u16) -> Nat {
    Nat {
        inside: addr(CLIENT, 1000),
        outside: addr(CLIENT, port),
    }
}

fn requests(peer: &Peer, from: usize) -> Vec<Message> {
    peer.sent[from..]
        .iter()
        .filter_map(|raw| {
            let mut m = Message {
                raw: raw.clone(),
                ..Default::default()
            };
            m.decode().ok()?;
            (m.typ.class == CLASS_REQUEST).then_some(m)
        })
        .collect()
}

/// A check for `username`, signed with `key`, as the client would send it.
fn check(username: String, key: String, use_candidate: bool) -> Message {
    let crypto_provider = provider();
    let mut setters: Vec<Box<dyn Setter>> = vec![
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
        Box::new(AttrControlling(7)),
    ];
    if use_candidate {
        setters.push(Box::<UseCandidateAttr>::default());
    }
    setters.push(Box::new(
        MessageIntegrity::new_short_term_integrity_with_provider(key, crypto_provider.crypto()),
    ));
    setters.push(Box::new(FINGERPRINT));
    let mut m = Message::new();
    m.build(&setters).unwrap();
    m
}

/// The username and key of a genuine check from `client` to `sfu`.
fn genuine(client: &Peer, sfu: &Peer) -> (String, String) {
    let (sfu_creds, client_creds) = (
        sfu.agent.get_local_credentials(),
        client.agent.get_local_credentials(),
    );
    (
        format!("{}:{}", sfu_creds.ufrag, client_creds.ufrag),
        sfu_creds.pwd.clone(),
    )
}

fn deliver(sfu: &mut Peer, m: &Message, from: SocketAddr, now: Instant) {
    let _ = sfu.agent.handle_read(TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: addr(SFU, 2000),
            peer_addr: from,
            ecn: None,
            transport_protocol: TransportProtocol::UDP,
        },
        message: BytesMut::from(&m.raw[..]),
    });
}

fn selected_is(sfu: &Peer, client_port: u16) -> bool {
    sfu.selected_pair() == Some((addr(SFU, 2000), addr(CLIENT, client_port)))
}

#[test]
fn test_controlling_agent_nominates_every_check_toward_a_lite_peer() {
    for (remote_lite, nominates) in [(true, true), (false, false)] {
        let (mut client, mut sfu, mut clock) = connected(remote_lite);
        let from = client.sent.len();
        run(&mut client, &mut sfu, &mut clock, 6000);
        let checks = requests(&client, from);
        assert!(!checks.is_empty(), "consent checks keep going");
        for m in checks {
            assert_eq!(
                nominates,
                m.contains(ATTR_USE_CANDIDATE),
                "remote_lite={remote_lite}"
            );
        }
    }
}

#[test]
fn test_lite_agent_follows_a_client_that_nominates_from_a_new_address() {
    let (mut client, mut sfu, mut clock) = connected(true);
    run_behind(&mut client, &mut sfu, &mut clock, 6000, &nat_to(1500));

    assert!(selected_is(&sfu, 1500));
    assert_eq!(ConnectionState::Connected, sfu.agent.state());
    assert_eq!(ConnectionState::Connected, client.agent.state());
    assert!(
        !sfu.states.contains(&ConnectionState::Disconnected),
        "the move came before the old address went quiet"
    );

    run_behind(&mut client, &mut sfu, &mut clock, 6000, &nat_to(1600));
    assert!(selected_is(&sfu, 1600), "and again");
}

#[test]
fn test_a_check_without_use_candidate_from_a_new_address_does_not_move_the_pair() {
    let (client, mut sfu, clock) = connected(false);
    let (username, key) = genuine(&client, &sfu);
    let moved = addr(CLIENT, 1500);
    deliver(&mut sfu, &check(username, key, false), moved, clock);

    assert!(selected_is(&sfu, 1000));
    assert!(
        sfu.agent
            .get_remote_candidates()
            .iter()
            .any(|c| c.addr() == moved),
        "the address is learned as a peer-reflexive candidate"
    );
}

#[test]
fn test_unauthenticated_checks_from_a_new_address_move_nothing() {
    let (client, mut sfu, clock) = connected(true);
    let candidates = sfu.agent.get_remote_candidates().len();
    let (username, key) = genuine(&client, &sfu);

    let forged_key = check(username.clone(), "not-the-password".to_owned(), true);
    deliver(&mut sfu, &forged_key, addr(CLIENT, 1500), clock);
    let forged_user = check(format!("{username}x"), key, true);
    deliver(&mut sfu, &forged_user, addr(CLIENT, 1501), clock);

    assert!(selected_is(&sfu, 1000));
    assert_eq!(candidates, sfu.agent.get_remote_candidates().len());
}
