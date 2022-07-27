use crate::net::peers::AnyPeerConnections;
use crate::PeerId;
use async_trait::async_trait;
use rand::{CryptoRng, RngCore};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::BTreeMap;

/// Part of a config that needs to be generated to bootstrap a new federation.
#[async_trait(?Send)]
pub trait GenerateConfig: Sized {
    type Params: ?Sized;
    type ClientConfig;
    type ConfigMessage;
    type ConfigError;

    /// Function that generates the config of all peers locally. This is only meant to be used for
    /// testing as the generating machine would be a single point of failure/compromise.
    fn trusted_dealer_gen(
        peers: &[PeerId],
        max_evil: usize,
        params: &Self::Params,
        rng: impl RngCore + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig);

    async fn distributed_gen(
        connections: AnyPeerConnections<Self::ConfigMessage>,
        our_id: &PeerId,
        peers: &[PeerId],
        max_evil: usize,
        params: &Self::Params,
        rng: impl RngCore + CryptoRng,
    ) -> Result<(Self, Self::ClientConfig), Self::ConfigError>;
}

pub async fn receive_all<T: Serialize + DeserializeOwned + Unpin + Send>(
    connections: &mut AnyPeerConnections<T>,
    our_id: &PeerId,
    peers: &[PeerId],
) -> BTreeMap<PeerId, T> {
    let mut received: BTreeMap<PeerId, T> = BTreeMap::new();

    for _ in 1..peers.len() {
        let (peer, msg) = connections.receive().await;
        received.insert(peer, msg);
    }

    for peer in peers {
        if peer != our_id {
            received.get(peer).expect("Peer key not found");
        }
    }

    received
}
