use async_trait::async_trait;
use minimint_api::config::GenerateConfig;
use minimint_api::net::peers::AnyPeerConnections;
use minimint_api::PeerId;
use secp256k1::rand::{CryptoRng, RngCore as RngCore06};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use threshold_crypto::ff::Field;
use threshold_crypto::group::{CurveAffine, CurveProjective};
use threshold_crypto::poly::{BivarCommitment, BivarPoly, Poly};
use threshold_crypto::{Fr, G1Affine, PublicKeySet, SecretKeyShare, G1};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningModuleConfig {
    pub threshold_pub_keys: threshold_crypto::PublicKeySet,
    // TODO: propose serde(with = "…") based protection upstream instead
    pub threshold_sec_key:
        threshold_crypto::serde_impl::SerdeSecret<threshold_crypto::SecretKeyShare>,
    pub threshold: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningModuleClientConfig {
    pub threshold_pub_key: threshold_crypto::PublicKey,
}

struct Rand07Compat<R: RngCore06>(R);

impl<R: RngCore06> rand07::RngCore for Rand07Compat<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand07::Error> {
        self.0.try_fill_bytes(dest).map_err(rand07::Error::new)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum KeyGen {
    Commit(Poly, BivarCommitment),
    Verify(#[serde(with = "serde_g1")] G1),
}

#[async_trait(?Send)]
impl GenerateConfig for LightningModuleConfig {
    type Params = ();
    type ClientConfig = LightningModuleClientConfig;
    type ConfigMessage = KeyGen;
    type ConfigError = ();

    fn trusted_dealer_gen(
        peers: &[PeerId],
        max_evil: usize,
        _params: &Self::Params,
        rng: impl RngCore06 + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig) {
        let threshold = peers.len() - max_evil;
        let sks = threshold_crypto::SecretKeySet::random(threshold - 1, &mut Rand07Compat(rng));
        let pks = sks.public_keys();

        let server_cfg = peers
            .iter()
            .map(|&peer| {
                let sk = sks.secret_key_share(peer.to_usize());

                (
                    peer,
                    LightningModuleConfig {
                        threshold_pub_keys: pks.clone(),
                        threshold_sec_key: threshold_crypto::serde_impl::SerdeSecret(sk),
                        threshold,
                    },
                )
            })
            .collect();

        let client_cfg = LightningModuleClientConfig {
            threshold_pub_key: pks.public_key(),
        };

        (server_cfg, client_cfg)
    }

    async fn distributed_gen(
        mut connections: AnyPeerConnections<Self::ConfigMessage>,
        our_id: &PeerId,
        peers: &[PeerId],
        max_evil: usize,
        _params: &Self::Params,
        rng: impl RngCore06 + CryptoRng,
    ) -> Result<(Self, Self::ClientConfig), Self::ConfigError> {
        let threshold = peers.len() - max_evil;
        let mut rand = Rand07Compat(rng);
        let mut sk = Fr::zero();
        let mut pk = Poly::zero().commitment();

        for peer in peers {
            let (poly, commit) = if peer == our_id {
                let our_poly = BivarPoly::random(threshold - 1, &mut rand);
                let our_commit = BivarPoly::commitment(&our_poly);

                for peer in peers {
                    let msg = KeyGen::Commit(our_poly.row(peer.as_row()), our_commit.clone());
                    connections.send(&[*peer], msg).await;
                }

                (our_poly.row(our_id.as_row()), our_commit)
            } else {
                match connections.receive().await {
                    (p, KeyGen::Commit(poly, commit)) if &p == peer => (poly, commit),
                    msg => panic!("Unexpected message {:?}", msg),
                }
            };

            // verify the commitment
            assert_eq!(poly.commitment(), commit.row(our_id.as_row()));
            for peer in peers {
                let val = poly.evaluate(peer.as_row());
                let val_g1 = G1Affine::one().mul(val).into_affine().into_projective();
                connections.send(&[*peer], KeyGen::Verify(val_g1)).await;
            }
            let verifies = minimint_api::config::receive_all(&mut connections, our_id, peers).await;
            for (peer, msg) in verifies.iter() {
                match msg {
                    KeyGen::Verify(val_g1) => {
                        assert_eq!(&commit.evaluate(peer.as_row(), our_id.as_row()), val_g1)
                    }
                    msg => panic!("Unexpected message {:?}", msg),
                }
            }

            // add to our secret key and public key
            sk.add_assign(&poly.evaluate(Fr::zero()));
            pk += commit.row(0_usize);
        }

        let threshold_pub_key = PublicKeySet::from(pk);
        let sk = SecretKeyShare::from_mut(&mut sk);

        let server_cfg = LightningModuleConfig {
            threshold_pub_keys: threshold_pub_key.clone(),
            threshold_sec_key: threshold_crypto::serde_impl::SerdeSecret(sk),
            threshold,
        };

        let client_cfg = LightningModuleClientConfig {
            threshold_pub_key: threshold_pub_key.public_key(),
        };

        Ok((server_cfg, client_cfg))
    }
}

mod serde_g1 {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};
    use threshold_crypto::group::{CurveAffine, CurveProjective, EncodedPoint};
    use threshold_crypto::pairing::bls12_381::G1Compressed;
    use threshold_crypto::G1;

    pub fn serialize<S>(key: &G1, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.into_affine().into_compressed();
        serializer.serialize_bytes(bytes.as_ref())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<G1, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 48 {
            return Err(D::Error::invalid_length(bytes.len(), &"48 bytes"));
        }
        let mut g1 = G1Compressed::empty();
        g1.as_mut().copy_from_slice(&bytes);
        Ok(g1.into_affine().unwrap().into_projective())
    }
}

trait PeerRow {
    fn as_row(&self) -> usize;
}

impl PeerRow for PeerId {
    fn as_row(&self) -> usize {
        (u16::from(*self) as usize) + 1
    }
}

#[test]
fn test_g1_serde() {
    let g1 = KeyGen::Verify(G1::random(&mut Rand07Compat(secp256k1::rand::thread_rng())));
    let g1_deser = serde_json::from_str(&serde_json::to_string(&g1).unwrap()).unwrap();
    assert_eq!(g1, g1_deser);
}

#[test]
fn test_threshold_sigs() {
    let peers = 4;
    let max_evil = 1;
    let threshold = peers - max_evil;

    let polys: Vec<BivarPoly> = (0..peers)
        .map(|_| {
            BivarPoly::random(
                threshold - 1,
                &mut Rand07Compat(secp256k1::rand::thread_rng()),
            )
        })
        .collect();
    let commits = polys.iter().map(BivarPoly::commitment);

    let mut sum_commit = Poly::zero().commitment();

    let mut sks: Vec<Fr> = vec![Fr::zero(); peers];
    for (our_poly, commit) in polys.iter().zip(commits) {
        for (i, sk) in sks.iter_mut().enumerate() {
            let poly = our_poly.row(i + 1);
            assert_eq!(poly.commitment(), commit.row(i + 1));

            for j in 0..polys.len() {
                let val = poly.evaluate(j + 1);
                let val_g1 = G1Affine::one().mul(val);
                assert_eq!(commit.evaluate(i + 1, j + 1), val_g1);
            }

            sk.add_assign(&poly.evaluate(Fr::zero()));
        }
        sum_commit += commit.row(0_usize);
    }

    let threshold_pub_key = PublicKeySet::from(sum_commit);

    let msg = b"Totally real news";
    let ciphertext = threshold_pub_key.public_key().encrypt(&msg[..]);

    let shares: BTreeMap<_, _> = sks
        .iter_mut()
        .enumerate()
        .take(threshold)
        .map(|(i, sk)| {
            let dec_share = SecretKeyShare::from_mut(sk)
                .decrypt_share(&ciphertext)
                .expect("ciphertext is invalid");
            (i, dec_share)
        })
        .collect();

    let decrypted = threshold_pub_key
        .decrypt(&shares, &ciphertext)
        .expect("decryption shares match");
    assert_eq!(msg[..], decrypted[..]);
}
