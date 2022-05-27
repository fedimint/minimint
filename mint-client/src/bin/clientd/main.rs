mod router;

use crate::router::{Router, Shared};

use bitcoin_hashes::hex::ToHex;
use clap::Parser;
use minimint::config::load_from_file;
use minimint::modules::mint::tiered::coins::Coins;
use minimint::outcome::TransactionStatus;
use minimint_api::Amount;
use mint_client::clients::user::ClientError;
use mint_client::jsonrpc::error::{standard_error, RpcError, StandardError};
use mint_client::jsonrpc::json::*;
use mint_client::ln::gateway::LightningGateway;
use mint_client::mint::SpendableCoin;
use mint_client::{ClientAndGatewayConfig, UserClient};
use rand::rngs::OsRng;
use reqwest::StatusCode;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::info;
use tracing_subscriber::EnvFilter;
#[derive(Clone)]
pub struct State {
    shared: Arc<Shared>,
}

#[derive(Parser)]
struct Options {
    workdir: PathBuf,
}

#[tokio::main]
async fn main() -> tide::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let opts: Options = Options::parse();
    let cfg_path = opts.workdir.join("client.json");
    let db_path = opts.workdir.join("client.db");
    let cfg: ClientAndGatewayConfig = load_from_file(&cfg_path);
    let db = sled::open(&db_path)
        .unwrap()
        .open_tree("mint-client")
        .unwrap();
    let client = UserClient::new(cfg.client, Box::new(db), Default::default());
    let rng = rand::rngs::OsRng::new().unwrap();
    let router = Router::new()
        .add_handler("info", info)
        .add_handler("pending", pending)
        .add_handler("events", events)
        .add_handler("pegin_address", pegin_address)
        .add_handler("pegin", pegin)
        .add_handler("pegout", pegout)
        .add_handler("spend", spend)
        .add_handler("lnpay", ln_pay)
        .add_handler("reissue", reissue)
        .add_handler("reissue_validate", reissue_validate);
    let sclient = Arc::new(client);
    let sevents = Arc::new(EventLog::new(21));

    let shared = Shared {
        client: Arc::clone(&sclient),
        gateway: Arc::new(cfg.gateway.clone()),
        events: Arc::clone(&sevents),
        rng,
        router: Arc::new(router),
        spend_lock: Arc::new(Mutex::new(())),
    };
    let state = State {
        shared: Arc::new(shared),
    };
    let mut app = tide::with_state(state);

    app.at("/rpc")
        .post(|mut req: tide::Request<State>| async move {
            let mut response: Vec<Response> = Vec::new();
            /*
            This looks a bit silly but for example: request -> response and NOT request [response] but [request, notification] SHOULD -> [response]
             */
            let mut was_batch = false;
            if let Ok(req_obj) = req.body_json::<serde_json::Value>().await {
                let batch = req_obj.as_array().cloned().unwrap_or_else(||vec![req_obj]);
                was_batch = batch.len() > 1;
                for json in batch {
                    let shared = Arc::clone(&req.state().shared);
                    let router = shared.router.clone();

                    if let Ok(request_object) = Request::deserialize(json) {
                        //Valid Request Object
                        if  Some(String::from(JSON_RPC)) == request_object.jsonrpc {
                            //Valid JSON-2.0
                            if let Some(id) = request_object.id {
                                // not a notification
                                if let Some(handler) = router.get(request_object.method.as_str()) {
                                    //There is a handler (method)
                                    match handler.call(request_object.params, Arc::clone(&shared)).await {
                                        Ok(handler_res) => {
                                            //Success, response will be send to client
                                            response.push(Response::with_result(handler_res, id));
                                        }
                                        Err(err) => {
                                            //Either the params were wrong or there was an internal error
                                            response.push(Response::with_error(err, Some(id)));
                                        }
                                    }
                                } else {
                                    //Method not found
                                    let err = standard_error(StandardError::MethodNotFound, None);
                                    response.push(Response::with_error(err, None));
                                }
                            } else {
                                // a notification
                                tokio::spawn(async move{
                                    if let Some(handler) = router.get(request_object.method.as_str()) {
                                        //There is a handler (method)
                                        #[allow(unused_must_use)]
                                        { handler.call(request_object.params, Arc::clone(&shared)).await; }
                                    }
                                });
                                continue;
                            }
                        } else{
                            //Invalid JSON-RPC version
                            let err = standard_error(StandardError::InvalidRequest, Some(
                                serde_json::Value::String(String::from("please make sure your request follows the JSON-RPC 2.0 specification"))
                            ));
                            response.push(Response::with_error(err, None));
                        }
                    } else {
                        //Invalid Request Object
                        let err = standard_error(StandardError::InvalidRequest, None);
                        response.push(Response::with_error(err, None))
                    }
                }
            } else {
                //Invalid JSON
                let err = standard_error(StandardError::ParseError, None);
                response.push(Response::with_error(err, None))
            };
            let body = if !was_batch {
                tide::Body::from_json(&response.pop()).unwrap_or_else(|_| tide::Body::empty())
            } else {
                tide::Body::from_json(&response).unwrap_or_else(|_| tide::Body::empty())
            };
            let mut res = tide::Response::new(200);
            res.set_body(body);
            Ok(res)
        });
    tokio::spawn(async move {
        loop {
            if !&sclient.fetch_active_issuances().is_empty() {
                fetch(Arc::clone(&sclient), Arc::clone(&sevents)).await;
            }
            //wait for some time ??
        }
    });
    app.listen("127.0.0.1:8081").await?;
    Ok(())
}

async fn info(_: serde_json::Value, shared: Arc<Shared>) -> Result<serde_json::Value, RpcError> {
    let client = Arc::clone(&shared.client);
    let cfd = client.fetch_active_issuances();
    let result = serde_json::json!(&RpcResult::Info(InfoResult::build(client.coins(), cfd)));
    Ok(result)
}
async fn pending(_: serde_json::Value, shared: Arc<Shared>) -> Result<serde_json::Value, RpcError> {
    let client = &shared.client;
    let cfd = client.fetch_active_issuances();
    let result = serde_json::json!(&RpcResult::Pending(PendingResult::build(cfd)));
    Ok(result)
}
async fn events(
    params: serde_json::Value,
    shared: Arc<Shared>,
) -> Result<serde_json::Value, RpcError> {
    let timestamp: u64 = u64::deserialize(params).map_err(|e| {
        standard_error(
            StandardError::InvalidParams,
            Some(serde_json::Value::String(format!("{:?}", e))),
        )
    })?;
    let events = Arc::clone(&shared.events);
    let events = events.get(timestamp);
    let result = serde_json::json!(&RpcResult::Events(EventsResult::build(events)));
    Ok(result)
}
async fn pegin_address(
    _: serde_json::Value,
    shared: Arc<Shared>,
) -> Result<serde_json::Value, RpcError> {
    let client = Arc::clone(&shared.client);
    let mut rng = shared.rng.clone();
    let result = serde_json::json!(&RpcResult::PegInAddress(PegInAddressResult::build(
        client.get_new_pegin_address(&mut rng)
    )));
    Ok(result)
}
async fn pegin(
    params: serde_json::Value,
    shared: Arc<Shared>,
) -> Result<serde_json::Value, RpcError> {
    let client = Arc::clone(&shared.client);
    let mut rng = shared.rng.clone();
    //If Parsing fails here it is NOT a parsing error since we only call this function if we've got valid json, so it must be wrong params
    let pegin: PegInReq = PegInReq::deserialize(params).map_err(|e| {
        standard_error(
            StandardError::InvalidParams,
            Some(serde_json::Value::String(format!("{:?}", e))),
        )
    })?;
    let txout_proof = pegin.txout_proof;
    let transaction = pegin.transaction;
    let txid = client.peg_in(txout_proof, transaction, &mut rng).await?;
    info!("Started peg-in {}, result will be fetched", txid.to_hex());
    let result = serde_json::json!(&RpcResult::PegInOut(PegInOutResult::build(txid)));
    Ok(result)
}
async fn pegout(
    params: serde_json::Value,
    shared: Arc<Shared>,
) -> Result<serde_json::Value, RpcError> {
    let mut rng = shared.rng.clone();
    let client = Arc::clone(&shared.client);
    //If Parsing fails here it is NOT a parsing error since we only call this function if we've got valid json, so it must be wrong params
    let pegout: PegOutReq = PegOutReq::deserialize(params).map_err(|e| {
        standard_error(
            StandardError::InvalidParams,
            Some(serde_json::Value::String(format!("{:?}", e))),
        )
    })?;
    let txid = client
        .peg_out(pegout.amount, pegout.address, &mut rng)
        .await?;
    let result = serde_json::json!(&RpcResult::PegInOut(PegInOutResult::build(txid)));
    Ok(result)
}
async fn spend(
    params: serde_json::Value,
    shared: Arc<Shared>,
) -> Result<serde_json::Value, RpcError> {
    //If Parsing fails here it is NOT a parsing error since we only call this function if we've got valid json, so it must be wrong params
    let value: u64 = u64::deserialize(params).map_err(|e| {
        standard_error(
            StandardError::InvalidParams,
            Some(serde_json::Value::String(format!("{:?}", e))),
        )
    })?;
    let client = &shared.client;
    //just calling lock without binding it to a variable would do nothing because it would lock and then unlock immediately
    let drop_when_finished = shared.spend_lock.lock();
    let amount = Amount::from_msat(value);
    let res = match client.select_and_spend_coins(amount) {
        Ok(outgoing_coins) => RpcResult::Spend(SpendResult::build(outgoing_coins)),
        Err(e) => {
            return Err(ClientError::from(e).into());
        }
    };
    std::mem::drop(drop_when_finished);
    let result = serde_json::json!(&res);
    Ok(result)
}
async fn ln_pay(
    params: serde_json::Value,
    shared: Arc<Shared>,
) -> Result<serde_json::Value, RpcError> {
    let client = Arc::clone(&shared.client);
    let gateway = Arc::clone(&shared.gateway);
    //If Parsing fails here it is NOT a parsing error since we only call this function if we've got valid json, so it must be wrong params
    let invoice: InvoiceReq = InvoiceReq::deserialize(params).map_err(|e| {
        standard_error(
            StandardError::InternalError,
            Some(serde_json::Value::String(format!("{:?}", e))),
        )
    })?;
    let rng = shared.rng.clone();
    let res = pay_invoice(
        invoice.bolt11,
        client,
        gateway,
        rng,
        Arc::clone(&shared.spend_lock),
    )
    .await?;

    if let StatusCode::OK = res.status() {
        let result = serde_json::json!(&RpcResult::LnPay(LnPayResult::build(
            "successful ln-payment".to_string(),
        )));
        Ok(result)
    } else {
        Err(standard_error(
            StandardError::InternalError,
            Some(serde_json::Value::String(String::from(
                "Error: Payment failed !", //TODO: get a more useful error from the gateway
            ))),
        ))
    }
}
async fn reissue(
    params: serde_json::Value,
    shared: Arc<Shared>,
) -> Result<serde_json::Value, RpcError> {
    //If Parsing fails here it is NOT a parsing error since we only call this function if we've got valid json, so it must be wrong params
    let coins: Coins<SpendableCoin> = Coins::deserialize(params).map_err(|e| {
        standard_error(
            StandardError::InternalError,
            Some(serde_json::Value::String(format!("{:?}", e))),
        )
    })?;
    let client = Arc::clone(&shared.client);
    let events = Arc::clone(&shared.events);
    tokio::spawn(async move {
        let mut rng = shared.rng.clone();
        let out_point = match client.reissue(coins, &mut rng).await {
            Ok(o) => o,
            Err(e) => {
                events.add(format!("{:?}", e));
                return;
            }
        };

        if let Err(e) = client.fetch_tx_outcome(out_point.txid, true).await {
            events.add(format!("{:?}", e));
        }
    });
    Ok(serde_json::Value::Null)
}
async fn reissue_validate(
    params: serde_json::Value,
    shared: Arc<Shared>,
) -> Result<serde_json::Value, RpcError> {
    //If Parsing fails here it is NOT a parsing error since we only call this function if we've got valid json, so it must be wrong params
    let coins: Coins<SpendableCoin> = Coins::deserialize(params).map_err(|e| {
        standard_error(
            StandardError::InternalError,
            Some(serde_json::Value::String(format!("{:?}", e))),
        )
    })?;
    let client = Arc::clone(&shared.client);
    let mut rng = shared.rng.clone();
    let out_point = client.reissue(coins, &mut rng).await?;
    //This has to be changed : endless loop possible (polling=true)
    let status = match client.fetch_tx_outcome(out_point.txid, true).await {
        Err(e) => TransactionStatus::Error(e.to_string()),
        Ok(s) => s,
    };
    let result = serde_json::json!(&RpcResult::Reissue(ReissueResult::build(out_point, status)));
    Ok(result)
}

///Uses the [`UserClient`] to fetch the newly issued or reissued coins
async fn fetch(client: Arc<UserClient>, events: Arc<EventLog>) {
    match client.fetch_all_coins().await {
        Ok(txids) => events.add(format!("successfully fetched: {:?}", txids)),
        Err(e) => events.add(format!("{:?}", e)),
    }
}

async fn pay_invoice(
    bolt11: lightning_invoice::Invoice,
    client: Arc<UserClient>,
    gateway: Arc<LightningGateway>,
    mut rng: OsRng,
    lock: Arc<Mutex<()>>,
) -> Result<reqwest::Response, ClientError> {
    let http = reqwest::Client::new();

    let contract_id = client
        .fund_outgoing_ln_contract(&*gateway, bolt11, &mut rng, lock)
        .await?;

    client
        .wait_contract_timeout(contract_id, Duration::from_secs(5))
        .await?;

    info!(
        "Funded outgoing contract {}, notifying gateway",
        contract_id
    );

    http.post(&format!("{}/pay_invoice", &*gateway.api))
        .json(&contract_id)
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .map_err(|_| ClientError::FailSendInvoicePay) //TODO: get a more useful error from the gateway
}
