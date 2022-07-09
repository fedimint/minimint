use clap::Parser;
use ln_gateway::LnGatewayConfig;
use minimint::config::load_from_file;
use mint_client::clients::gateway::GatewayClientConfig;
use mint_client::ln::gateway::LightningGateway;
use mint_client::ClientAndGatewayConfig;
use rand::thread_rng;
use secp256k1::{KeyPair, PublicKey, Secp256k1};
use std::path::PathBuf;

#[derive(Parser)]
struct Opts {
    workdir: PathBuf,
    ln_rpc_path: PathBuf,
    ln_node_pub_key: PublicKey,
}

fn main() {
    let opts = Opts::parse();
    let federation_client_cfg_path = opts.workdir.join("federation_client.json");
    let federation_client_cfg: minimint::config::ClientConfig =
        load_from_file(&federation_client_cfg_path);

    let mut rng = thread_rng();
    let ctx = Secp256k1::new();

    let kp = KeyPair::new(&ctx, &mut rng);

    let gateway_cfg = LnGatewayConfig {
        federation_client: GatewayClientConfig {
            common: federation_client_cfg.clone(),
            redeem_key: kp,
            timelock_delta: 10,
        },
        ln_socket: opts.ln_rpc_path,
    };

    let gw_cfg_file_path: PathBuf = opts.workdir.join("gateway.json");
    let gw_cfg_file = std::fs::File::create(gw_cfg_file_path).expect("Could not create cfg file");
    serde_json::to_writer_pretty(gw_cfg_file, &gateway_cfg).unwrap();

    let client_cfg = ClientAndGatewayConfig {
        client: federation_client_cfg,
        gateway: LightningGateway {
            mint_pub_key: kp.public_key(),
            node_pub_key: opts.ln_node_pub_key,
            api: "http://127.0.0.1:8080".to_string(),
        },
    };

    let client_cfg_file_path: PathBuf = opts.workdir.join("client.json");
    let client_cfg_file =
        std::fs::File::create(client_cfg_file_path).expect("Could not create cfg file");
    serde_json::to_writer_pretty(client_cfg_file, &client_cfg).unwrap();
}
