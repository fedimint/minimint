use crate::jsonrpc::error::Error;
use crate::jsonrpc::json::{
    EventsResult, InfoResult, InvoiceReq, LnPayResult, PegInAddressResult, PegInOutResult,
    PegInReq, PegOutReq, PendingResult, ReissueResult, Request, Response, RpcResult, SpendResult,
};
use crate::mint::SpendableCoin;
use minimint::modules::mint::tiered::coins::Coins;
use minimint_api::Amount;
use serde::Deserialize;

const DEFAULT_ID: &str = "1";
pub struct JsonRpc {
    client: reqwest::Client,
    host: String,
}
impl JsonRpc {
    pub fn new(host: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            host,
        }
    }

    async fn call(&self, request_object: Request) -> Result<RpcResult, Error> {
        let response = self
            .client
            .post(self.host.as_str())
            .json(&request_object)
            .send()
            .await?;

        //note: not using response.json since it would consume response and it would demand different approach bellow
        let response = response.bytes().await?;
        if let Ok(serde_json::Value::Null) = serde_json::from_slice(&response) {
            //notification 'null' response
            Ok(RpcResult::Empty)
        } else {
            //non-notification with ...
            match serde_json::from_slice::<Response>(&response) {
                //... a result
                Ok(Response {
                    result: Some(result),
                    ..
                }) => Ok(RpcResult::deserialize(result).expect("can't fail")),
                //.. an error
                Ok(Response {
                    error: Some(error), ..
                }) => Err(Error::Rpc(error)),
                //either not a valid Response object OR a valid response with neither a result or error
                _ => panic!("this should not be reached"),
            }
        }
    }
    #[allow(dead_code)]
    pub async fn get_info(&self) -> Result<InfoResult, Error> {
        let result = self
            .call(Request::standard("info", Some(DEFAULT_ID)))
            .await?;
        if let RpcResult::Info(result) = result {
            Ok(result)
        } else {
            Err(Error::ResultMissmatch)
        }
    }
    #[allow(dead_code)]
    pub async fn get_pending(&self) -> Result<PendingResult, Error> {
        let result = self
            .call(Request::standard("pending", Some(DEFAULT_ID)))
            .await?;
        if let RpcResult::Pending(result) = result {
            Ok(result)
        } else {
            Err(Error::ResultMissmatch)
        }
    }
    #[allow(dead_code)]
    pub async fn get_events(&self, params: u64) -> Result<EventsResult, Error> {
        let result = self
            .call(Request::standard_with_params(
                "events",
                params,
                Some(DEFAULT_ID),
            ))
            .await?;
        if let RpcResult::Events(result) = result {
            Ok(result)
        } else {
            Err(Error::ResultMissmatch)
        }
    }
    #[allow(dead_code)]
    pub async fn get_new_pegin_address(&self) -> Result<PegInAddressResult, Error> {
        let result = self
            .call(Request::standard("pegin_address", Some(DEFAULT_ID)))
            .await?;
        if let RpcResult::PegInAddress(result) = result {
            Ok(result)
        } else {
            Err(Error::ResultMissmatch)
        }
    }
    #[allow(dead_code)]
    pub async fn peg_in(&self, params: PegInReq) -> Result<PegInOutResult, Error> {
        let result = self
            .call(Request::standard_with_params(
                "pegin",
                params,
                Some(DEFAULT_ID),
            ))
            .await?;
        if let RpcResult::PegInOut(result) = result {
            Ok(result)
        } else {
            Err(Error::ResultMissmatch)
        }
    }
    #[allow(dead_code)]
    pub async fn peg_out(&self, params: PegOutReq) -> Result<PegInOutResult, Error> {
        let result = self
            .call(Request::standard_with_params(
                "pegout",
                params,
                Some(DEFAULT_ID),
            ))
            .await?;
        if let RpcResult::PegInOut(result) = result {
            Ok(result)
        } else {
            Err(Error::ResultMissmatch)
        }
    }
    #[allow(dead_code)]
    pub async fn spend(&self, params: Amount) -> Result<SpendResult, Error> {
        let result = self
            .call(Request::standard_with_params(
                "spend",
                params.milli_sat,
                Some(DEFAULT_ID),
            ))
            .await?;
        if let RpcResult::Spend(result) = result {
            Ok(result)
        } else {
            Err(Error::ResultMissmatch)
        }
    }
    #[allow(dead_code)]
    pub async fn lnpay(&self, params: InvoiceReq) -> Result<LnPayResult, Error> {
        let result = self
            .call(Request::standard_with_params(
                "lnpay",
                params,
                Some(DEFAULT_ID),
            ))
            .await?;
        if let RpcResult::LnPay(result) = result {
            Ok(result)
        } else {
            Err(Error::ResultMissmatch)
        }
    }
    #[allow(dead_code)]
    pub async fn reissue(&self, params: Coins<SpendableCoin>) -> Result<RpcResult, Error> {
        self.call(Request::standard_with_params(
            "reissue",
            params,
            Option::<()>::None,
        ))
        .await
    }
    #[allow(dead_code)]
    pub async fn reissue_validate(
        &self,
        params: Coins<SpendableCoin>,
    ) -> Result<ReissueResult, Error> {
        let result = self
            .call(Request::standard_with_params(
                "reissue",
                params,
                Some(DEFAULT_ID),
            ))
            .await?;
        if let RpcResult::Reissue(result) = result {
            Ok(result)
        } else {
            Err(Error::ResultMissmatch)
        }
    }
}
impl Default for JsonRpc {
    fn default() -> Self {
        Self::new(String::from("http://127.0.0.1:8081/rpc"))
    }
}

#[cfg(test)]
mod tests {
    use crate::jsonrpc::json::InvoiceReq;

    #[tokio::test]
    async fn serial() {
        //let rpc = Client::default();
        let bolt11 = "lnbcrt10m1p3g0wkfpp50gx8zyvhhk0s5spd2r63adlx7naxyf90epxyl6v6dft4dmnuq5rsdq8w3jhxaqcqp2sp5e9rsfjtzauerup7gqjzn4j4frqq4wvpr5822mv708q32jt84lyjq9qyysgqjx9tp29s9qkux69tqkezhyykj43xe2c5jswj3dxq546hk6cedkjs5zntn2mqu3rnxrvma6wperz5eh3pne96w5u9khxzs2636txudwgqnyp8s9";
        let invoice_request: InvoiceReq = InvoiceReq {
            bolt11: bolt11.parse::<lightning_invoice::Invoice>().unwrap(),
        };
        //Serialize InvReq
        let ir_serial = dbg!(serde_json::to_string(&invoice_request).unwrap());
        //Deserialize ir_serial in a new InvReq
        let back_inv_req: InvoiceReq = serde_json::from_str(ir_serial.as_str()).unwrap();
        assert_eq!(invoice_request.bolt11, back_inv_req.bolt11);
    }
}
