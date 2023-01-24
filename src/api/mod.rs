use crate::api::v2ray_rust_api::{
    GetLatencyRequest, GetLatencyResponse, GetStatsRequest, GetStatsResponse,
};
use crate::config::COUNTER_MAP;
use crate::proxy::{Address, ChainStreamBuilder};

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::future::join_all;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use tonic::{Request, Response, Status};

pub mod v2ray_rust_api {
    tonic::include_proto!("v2ray.core.app.stats.command");
}

use v2ray_rust_api::latency_service_server::{LatencyService, LatencyServiceServer};
use v2ray_rust_api::stats_service_server::{StatsService, StatsServiceServer};

#[derive(Default)]
pub struct ApiServer;

impl ApiServer {
    pub(crate) fn new_server() -> StatsServiceServer<Self> {
        StatsServiceServer::new(Self)
    }
}

#[tonic::async_trait]
impl StatsService for ApiServer {
    async fn get_stats(
        &self,
        mut request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        let name = &request.get_ref().name;
        let reset = request.get_ref().reset;
        let ret_v;
        if let Some(v) = COUNTER_MAP.get().unwrap().get(name) {
            if reset {
                ret_v = v.swap(0, Relaxed);
            } else {
                ret_v = v.load(Relaxed);
            }
        } else {
            return Err(Status::new(tonic::Code::InvalidArgument, "name is invalid"));
        }
        Ok(Response::new(v2ray_rust_api::GetStatsResponse {
            stat: Some(v2ray_rust_api::Stat {
                name: std::mem::take(&mut request.get_mut().name),
                value: ret_v as i64,
            }),
        }))
    }
}

pub struct ApiLatencyServer {
    inner_map: Arc<HashMap<String, ChainStreamBuilder>>,
}
impl ApiLatencyServer {
    pub(crate) fn new_server(
        inner_map: Arc<HashMap<String, ChainStreamBuilder>>,
    ) -> LatencyServiceServer<Self> {
        LatencyServiceServer::new(Self { inner_map })
    }
}
#[tonic::async_trait]
impl LatencyService for ApiLatencyServer {
    async fn get_latency(
        &self,
        request: Request<GetLatencyRequest>,
    ) -> Result<Response<GetLatencyResponse>, Status> {
        if let Some(req) = &request.get_ref().outbound_name {
            if let Some(b) = self.inner_map.get(req) {
                let start = Instant::now();
                let stream = b
                    .build_tcp(
                        Address::from_str(request.get_ref().test_url.as_str()).map_err(|_| {
                            Status::new(tonic::Code::InvalidArgument, "test_url is invalid")
                        })?,
                    )
                    .await;
                let duration = start.elapsed();
                let mut latency_res = HashMap::new();
                if stream.is_err() {
                    latency_res.insert(req.clone(), -1i64);
                    return Ok(Response::new(GetLatencyResponse { latency_res }));
                } else {
                    latency_res.insert(req.clone(), duration.as_millis() as i64);
                    return Ok(Response::new(GetLatencyResponse { latency_res }));
                }
            } else {
                return Err(Status::new(tonic::Code::InvalidArgument, "name is invalid"));
            }
        } else {
            let mut vec_fut = Vec::new();
            let test_url = request.get_ref().test_url.as_str();
            let addr = Address::from_str(test_url)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "invalid test url"))?;
            for (name, _) in self.inner_map.iter() {
                let name = name.clone();
                let addr = addr.clone();
                vec_fut.push(async move {
                    let b = self.inner_map.get(&name).unwrap();
                    let start = Instant::now();
                    let timeout_stream = timeout(Duration::from_secs(5), async move {
                        b.build_tcp(addr).await?.write_u128(u128::MAX).await
                    })
                    .await;
                    let duration = start.elapsed();
                    if timeout_stream.is_err() {
                        return Ok::<(String, i64), std::io::Error>((name, -1i64));
                    } else {
                        let stream = timeout_stream?;
                        if stream.is_err() {
                            return Ok((name, -1i64));
                        }
                        return Ok((name, duration.as_millis() as i64));
                    }
                });
            }
            let vec_res = join_all(vec_fut).await;
            let mut latency_res = HashMap::new();
            for v in vec_res.into_iter() {
                let (k, v) = v?;
                latency_res.insert(k, v);
            }
            return Ok(Response::new(GetLatencyResponse { latency_res }));
        }
    }
}
