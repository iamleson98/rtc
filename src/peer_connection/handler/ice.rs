use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::event::{RTCEventInternal, TaggedRTCEventInternal};
use crate::peer_connection::message::internal::{
    RTCMessageInternal, STUNMessage, TaggedRTCMessageInternal,
};
use crate::peer_connection::transport::ice::IceTransport;
use crate::statistics::accumulator::RTCStatsAccumulator;
use crate::statistics::accumulator::ice_candidate_pair::PairTraffic;
use crate::statistics::stats::ice_candidate_pair::RTCStatsIceCandidatePairState;
use log::{debug, trace};
use shared::error::{Error, Result};
use shared::{TransportContext, TransportMessage};
use std::collections::VecDeque;
use std::time::Instant;

pub(crate) struct IceHandlerContext {
    pub(crate) ice_transport: IceTransport,

    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) event_outs: VecDeque<TaggedRTCEventInternal>,

    /// The selected candidate pair as the data path sees it: its stats key
    /// (`RTCIceCandidatePair_<local>_<remote>`, refreshed only when the selected pair
    /// changes) and the packets counted on it since the last [`Self::flush_traffic`].
    pub(crate) selected_pair: Option<SelectedPair>,

    /// The route the selected pair resolves to, with the agent's
    /// `selected_pair_generation` it was derived at. Packets reuse it until that moves.
    route: Option<(u64, Option<Route>)>,
}

/// The stats key and unflushed packet counts of the selected candidate pair.
pub(crate) struct SelectedPair {
    key: String,
    traffic: PairTraffic,
}

impl IceHandlerContext {
    pub(crate) fn new(ice_transport: IceTransport) -> Self {
        Self {
            ice_transport,

            read_outs: VecDeque::new(),
            write_outs: VecDeque::new(),
            event_outs: VecDeque::new(),

            selected_pair: None,
            route: None,
        }
    }

    /// Moves the packets counted on the selected pair into its stats accumulator.
    pub(crate) fn flush_traffic(&mut self, stats: &mut RTCStatsAccumulator) {
        if let Some(selected) = &mut self.selected_pair
            && let Some(pair) = stats.ice_candidate_pairs.get_mut(&selected.key)
        {
            pair.absorb(&mut selected.traffic);
        }
    }
}

/// IceHandler implements ICE Protocol handling
pub(crate) struct IceHandler<'a> {
    ctx: &'a mut IceHandlerContext,
    stats: &'a mut RTCStatsAccumulator,
}

impl<'a> IceHandler<'a> {
    pub(crate) fn new(ctx: &'a mut IceHandlerContext, stats: &'a mut RTCStatsAccumulator) -> Self {
        IceHandler { ctx, stats }
    }

    pub(crate) fn name(&self) -> &'static str {
        "IceHandler"
    }
}

/// Where the ICE agent has the selected candidate pair send from and to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Route {
    local_addr: std::net::SocketAddr,
    peer_addr: std::net::SocketAddr,
    transport_protocol: shared::TransportProtocol,
}

impl super::WriteBypass for IceHandler<'_> {
    fn write_in_place(&mut self, pending: &mut VecDeque<TaggedRTCMessageInternal>) -> bool {
        if !self.ctx.write_outs.is_empty() {
            return false;
        }
        match self.selected_route() {
            Some(route) => {
                for msg in pending.iter_mut() {
                    self.stamp(msg, route);
                }
            }
            None => {
                for msg in pending.drain(..) {
                    trace!(
                        "drop message from {:?} to {:?} before ICE connection is connected",
                        msg.transport.local_addr, msg.transport.peer_addr,
                    );
                }
            }
        }
        self.queue_agent_transmits(pending);
        true
    }
}

impl IceHandler<'_> {
    /// The route of the selected pair, derived once per change of the pair rather than per packet.
    fn selected_route(&mut self) -> Option<Route> {
        let generation = self.ctx.ice_transport.agent.selected_pair_generation();
        if let Some((cached, route)) = self.ctx.route
            && cached == generation
        {
            debug_assert_eq!(
                route,
                self.derive_route(),
                "the selected pair changed without its generation moving"
            );
            return route;
        }
        let route = self.derive_route();
        self.ctx.route = Some((generation, route));
        route
    }

    fn derive_route(&self) -> Option<Route> {
        self.ctx
            .ice_transport
            .agent
            .get_selected_candidate_pair()
            .map(|(local, remote)| Route {
                // Use the local candidate's base address: for (server/peer-)
                // reflexive candidates the candidate address is the NAT mapping,
                // not a bound local socket (RFC 8445 §5.1.1).
                local_addr: local.base_addr(),
                peer_addr: remote.addr(),
                transport_protocol: local.network_type().to_protocol(),
            })
    }

    /// Addresses `msg` with the selected candidate pair and counts it.
    ///
    /// The pair replaces local/peer addr and transport protocol: DTLS/SCTP endpoints run on
    /// placeholder transport contexts, so without the protocol rewrite their transmits stay
    /// stamped UDP even when the selected pair is TCP, and consumers routing poll_write() output by
    /// transport_protocol send every non-STUN packet down the wrong transport.
    fn stamp(&mut self, msg: &mut TaggedRTCMessageInternal, route: Route) {
        msg.transport.local_addr = route.local_addr;
        msg.transport.peer_addr = route.peer_addr;
        msg.transport.transport_protocol = route.transport_protocol;
        debug!("Bypass ice write {:?}", msg.transport.peer_addr);

        // Count on the selected pair; the stats accumulator takes the counts when read.
        if let Some(selected) = &mut self.ctx.selected_pair {
            selected.traffic.on_sent(msg.message.len(), msg.now);
        }
    }

    /// Puts what the agent has to send at the front of `queue`, in its own order.
    ///
    /// Control-plane first. The agent's transmits — an ICE nomination, a consent check
    /// — must reach the peer before any data-plane packet the pipeline already queued
    /// ahead of this call. The one that matters: the first DTLS ClientHello is queued
    /// the instant the controlling side selects (its own nomination's success
    /// response), and if it overtakes the nomination's USE-CANDIDATE request on the
    /// wire, the peer has not set its selected pair yet and drops it — a full
    /// retransmit cycle of otherwise-dead connect latency. Front-insertion keeps the
    /// agent's traffic first while preserving its own order.
    fn queue_agent_transmits(&mut self, queue: &mut VecDeque<TaggedRTCMessageInternal>) {
        use sansio::Protocol;

        let mut agent_transmits = Vec::new();
        while let Some(transmit) = self.ctx.ice_transport.agent.poll_write() {
            agent_transmits.push(TaggedRTCMessageInternal {
                now: transmit.now,
                transport: transmit.transport,
                message: RTCMessageInternal::Stun(STUNMessage::Raw(transmit.message)),
            });
        }
        for message in agent_transmits.into_iter().rev() {
            queue.push_front(message);
        }
    }
}

impl<'a>
    sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, TaggedRTCEventInternal>
    for IceHandler<'a>
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = TaggedRTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, mut msg: TaggedRTCMessageInternal) -> Result<()> {
        if let RTCMessageInternal::Stun(STUNMessage::Raw(message)) = msg.message {
            self.ctx.ice_transport.agent.handle_read(TransportMessage {
                now: msg.now,
                transport: msg.transport,
                message,
            })?;
        } else if self
            .ctx
            .ice_transport
            .agent
            .record_media_on_selected_pair(msg.now, msg.transport.peer_addr)
        {
            // only ICE connection is ready and bypass it
            debug!("bypass ice read {:?}", msg.transport.peer_addr);

            // Count on the selected pair; the stats accumulator takes the counts when read.
            if let Some(selected) = &mut self.ctx.selected_pair {
                selected.traffic.on_received(msg.message.len(), msg.now);
            }

            // When ICE restarts and the selected candidate pair changes,
            // WebRTC treats this as a path migration, and DTLS continues unchanged, bound to the ICE transport, not to a fixed 5-tuple.
            // Use default for transport to make DTLS tunneled
            msg.transport = TransportContext::default();
            self.ctx.read_outs.push_back(msg);
        } else {
            trace!(
                "drop message from {:?} to {:?} before ICE connection is connected",
                msg.transport.peer_addr, msg.transport.local_addr
            );
        }

        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, mut msg: TaggedRTCMessageInternal) -> Result<()> {
        match self.selected_route() {
            Some(route) => {
                self.stamp(&mut msg, route);
                self.ctx.write_outs.push_back(msg);
            }
            None => trace!(
                "drop message from {:?} to {:?} before ICE connection is connected",
                msg.transport.local_addr, msg.transport.peer_addr,
            ),
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        let mut write_outs = std::mem::take(&mut self.ctx.write_outs);
        self.queue_agent_transmits(&mut write_outs);
        self.ctx.write_outs = write_outs;
        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: TaggedRTCEventInternal) -> Result<()> {
        self.ctx.event_outs.push_back(evt);
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        if let Some(evt) = self.ctx.ice_transport.agent.poll_event() {
            // The agent stamps its own events, so this drain *propagates* that instant rather
            // than retaining one: the condition was observed when the agent saw it, not when
            // the pipeline got round to polling for it.
            let now = evt.now;
            match evt.event {
                ::ice::Event::ConnectionStateChange(state) => {
                    let ice_connection_state = state.into();
                    self.ctx.ice_transport.ice_connection_state = ice_connection_state;

                    // Update transport stats for ICE state change
                    // Use the original ice state which converts to RTCIceTransportState
                    self.stats.transport.on_ice_state_changed(state.into());

                    self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::RTCPeerConnectionEvent(
                            RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(
                                ice_connection_state,
                            ),
                        ),
                    });
                }
                ::ice::Event::SelectedCandidatePairChange(local, remote) => {
                    debug!(
                        "ice selected candidate pair {:?} <-> {:?}",
                        local.addr(),
                        remote.addr()
                    );

                    // Create/update the candidate pair accumulator
                    let pair = self
                        .stats
                        .get_or_create_candidate_pair(local.id(), remote.id());
                    pair.nominated = true;
                    pair.state = RTCStatsIceCandidatePairState::Succeeded;

                    // Packets counted so far belong to the pair being left.
                    self.ctx.flush_traffic(self.stats);
                    let key = format!("RTCIceCandidatePair_{}_{}", local.id(), remote.id());
                    self.ctx.selected_pair = Some(SelectedPair {
                        key: key.clone(),
                        traffic: PairTraffic::default(),
                    });
                    // Update transport stats for selected candidate pair change
                    self.stats.transport.on_selected_candidate_pair_changed(key);

                    self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::ICESelectedCandidatePairChange,
                    });
                }
                ::ice::Event::RoleChange(is_controlling) => {
                    self.stats.transport.on_ice_role_changed(is_controlling);
                }
                _ => {}
            }
        }

        super::pop_event(&mut self.ctx.event_outs)
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        self.ctx.ice_transport.agent.handle_timeout(now)
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.ctx.ice_transport.agent.poll_timeout()
    }

    fn close(&mut self) -> Result<()> {
        self.ctx.ice_transport.agent.close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_connection::transport::{RTCTransportId, TransportKind};
    use crate::statistics::accumulator::ice_candidate_pair::IceCandidatePairAccumulator;
    use ::ice::AgentConfig;
    use sansio::Protocol as _;
    use std::time::Duration;

    fn context() -> IceHandlerContext {
        let crypto_provider =
            crypto::default_provider().expect("a built-in crypto provider is enabled for tests");
        let transport = IceTransport::new(
            Instant::now(),
            AgentConfig::default(),
            crypto_provider,
            RTCTransportId::new(0xabcd_ef01_2345_6789, TransportKind::Ice),
        )
        .expect("ice transport");
        IceHandlerContext::new(transport)
    }

    fn select(ctx: &mut IceHandlerContext, stats: &mut RTCStatsAccumulator, key: &str) {
        ctx.flush_traffic(stats);
        stats
            .ice_candidate_pairs
            .entry(key.to_string())
            .or_insert_with(IceCandidatePairAccumulator::default);
        ctx.selected_pair = Some(SelectedPair {
            key: key.to_string(),
            traffic: PairTraffic::default(),
        });
    }

    fn count(ctx: &mut IceHandlerContext, sent: &[usize], received: &[usize], at: Instant) {
        let selected = ctx.selected_pair.as_mut().expect("a selected pair");
        for bytes in sent {
            selected.traffic.on_sent(*bytes, at);
        }
        for bytes in received {
            selected.traffic.on_received(*bytes, at);
        }
    }

    #[test]
    fn counts_reach_the_accumulator_when_flushed() {
        let mut ctx = context();
        let mut stats = RTCStatsAccumulator::new();
        let at = Instant::now();
        select(&mut ctx, &mut stats, "pair-a");

        count(&mut ctx, &[100; 7], &[40; 3], at);
        assert_eq!(stats.ice_candidate_pairs["pair-a"].packets_sent, 0);

        ctx.flush_traffic(&mut stats);
        let pair = &stats.ice_candidate_pairs["pair-a"];
        assert_eq!((pair.packets_sent, pair.bytes_sent), (7, 700));
        assert_eq!((pair.packets_received, pair.bytes_received), (3, 120));
        assert_eq!(pair.last_packet_sent_timestamp, Some(at));

        // Flushing is idempotent, and later counts add on.
        ctx.flush_traffic(&mut stats);
        count(&mut ctx, &[10], &[], at + Duration::from_millis(1));
        ctx.flush_traffic(&mut stats);
        let pair = &stats.ice_candidate_pairs["pair-a"];
        assert_eq!((pair.packets_sent, pair.bytes_sent), (8, 710));
        assert_eq!(pair.packets_received, 3);
    }

    #[test]
    fn a_route_change_keeps_each_pairs_own_counts() {
        let mut ctx = context();
        let mut stats = RTCStatsAccumulator::new();
        let at = Instant::now();
        select(&mut ctx, &mut stats, "pair-a");
        count(&mut ctx, &[100; 5], &[50; 2], at);

        // Renomination: what was counted so far belongs to the pair being left.
        select(&mut ctx, &mut stats, "pair-b");
        count(&mut ctx, &[200; 4], &[], at);
        ctx.flush_traffic(&mut stats);

        let a = &stats.ice_candidate_pairs["pair-a"];
        assert_eq!((a.packets_sent, a.bytes_sent), (5, 500));
        assert_eq!((a.packets_received, a.bytes_received), (2, 100));
        let b = &stats.ice_candidate_pairs["pair-b"];
        assert_eq!((b.packets_sent, b.bytes_sent), (4, 800));
        assert_eq!(b.packets_received, 0);

        // Back to the first pair: its counts continue rather than restart.
        select(&mut ctx, &mut stats, "pair-a");
        count(&mut ctx, &[1], &[], at);
        ctx.flush_traffic(&mut stats);
        assert_eq!(stats.ice_candidate_pairs["pair-a"].packets_sent, 6);
    }

    #[test]
    fn the_route_is_none_until_a_pair_is_selected_and_is_cached_per_generation() {
        let mut ctx = context();
        let mut stats = RTCStatsAccumulator::new();
        let mut handler = IceHandler {
            ctx: &mut ctx,
            stats: &mut stats,
        };
        assert!(handler.selected_route().is_none());
        let generation = handler.ctx.ice_transport.agent.selected_pair_generation();
        assert!(matches!(handler.ctx.route, Some((g, None)) if g == generation));
    }

    fn host(address: &str, port: u16) -> ::ice::candidate::Candidate {
        ::ice::candidate::candidate_host::CandidateHostConfig {
            base_config: ::ice::candidate::CandidateConfig {
                network: "udp".to_owned(),
                address: address.to_owned(),
                port,
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()
        .expect("host candidate")
    }

    fn peer_reflexive(address: &str, port: u16) -> ::ice::candidate::Candidate {
        ::ice::candidate::candidate_peer_reflexive::CandidatePeerReflexiveConfig {
            base_config: ::ice::candidate::CandidateConfig {
                network: "udp".to_owned(),
                address: address.to_owned(),
                port,
                component: 1,
                ..Default::default()
            },
            rel_addr: address.to_owned(),
            rel_port: port,
        }
        .new_candidate_peer_reflexive()
        .expect("peer reflexive candidate")
    }

    fn write(handler: &mut IceHandler<'_>) -> Option<TaggedRTCMessageInternal> {
        handler
            .handle_write(TaggedRTCMessageInternal {
                now: Instant::now(),
                transport: shared::TransportContext::default(),
                message: RTCMessageInternal::Raw(bytes::BytesMut::from(&[1u8][..])),
            })
            .expect("handle_write");
        handler.ctx.write_outs.pop_front()
    }

    /// Whatever moves the selected pair, the packet after it carries the pair's addresses: the
    /// cached route follows a renomination, a signaled candidate replacing a peer-reflexive one,
    /// and an ICE restart, after which nothing goes out until a pair is selected again.
    #[test]
    fn the_route_follows_the_selected_pair_through_every_way_it_changes() {
        let mut ctx = context();
        let mut stats = RTCStatsAccumulator::new();
        let local: std::net::SocketAddr = "192.168.0.2:777".parse().unwrap();
        let a: std::net::SocketAddr = "172.17.0.3:999".parse().unwrap();
        let b: std::net::SocketAddr = "172.17.0.4:998".parse().unwrap();
        let agent = &mut ctx.ice_transport.agent;
        agent.add_local_candidate(host("192.168.0.2", 777)).unwrap();
        agent
            .add_remote_candidate(peer_reflexive("172.17.0.3", 999))
            .unwrap();
        agent.add_remote_candidate(host("172.17.0.4", 998)).unwrap();
        let mut handler = IceHandler {
            ctx: &mut ctx,
            stats: &mut stats,
        };
        let peer_of = |msg: Option<TaggedRTCMessageInternal>| msg.map(|m| m.transport.peer_addr);

        handler
            .ctx
            .ice_transport
            .agent
            .select_pair_for_test(Instant::now(), local, a);
        assert_eq!(peer_of(write(&mut handler)), Some(a));
        // Stamped again from the cache.
        assert_eq!(peer_of(write(&mut handler)), Some(a));

        handler
            .ctx
            .ice_transport
            .agent
            .select_pair_for_test(Instant::now(), local, b);
        let sent = write(&mut handler).expect("sent on the renominated pair");
        assert_eq!(sent.transport.peer_addr, b);
        assert_eq!(sent.transport.local_addr, local);

        // The peer-reflexive remote of the selected pair is replaced by the signaled candidate
        // for the same address: the route is derived again and is the same.
        handler
            .ctx
            .ice_transport
            .agent
            .select_pair_for_test(Instant::now(), local, a);
        assert_eq!(peer_of(write(&mut handler)), Some(a));
        let before = handler.ctx.route.map(|(generation, _)| generation);
        handler
            .ctx
            .ice_transport
            .agent
            .add_remote_candidate(host("172.17.0.3", 999))
            .unwrap();
        assert_eq!(peer_of(write(&mut handler)), Some(a));
        assert_ne!(handler.ctx.route.map(|(generation, _)| generation), before);

        handler
            .ctx
            .ice_transport
            .agent
            .apply_restart(Instant::now(), false)
            .expect("restart");
        assert!(write(&mut handler).is_none(), "dropped after the restart");
        assert!(matches!(handler.ctx.route, Some((_, None))));
    }
}
