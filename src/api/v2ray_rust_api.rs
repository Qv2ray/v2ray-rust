#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetStatsRequest {
    /// Name of the stat counter.
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    /// Whether or not to reset the counter to fetching its value.
    #[prost(bool, tag="2")]
    pub reset: bool,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Stat {
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    #[prost(int64, tag="2")]
    pub value: i64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetStatsResponse {
    #[prost(message, optional, tag="1")]
    pub stat: ::core::option::Option<Stat>,
}
// message QueryStatsRequest {
//   string pattern = 1;
//   bool reset = 2;
// }

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryStatsResponse {
    #[prost(message, repeated, tag="1")]
    pub stat: ::prost::alloc::vec::Vec<Stat>,
}
/// Generated server implementations.
pub mod stats_service_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    ///Generated trait containing gRPC methods that should be implemented for use with StatsServiceServer.
    #[async_trait]
    pub trait StatsService: Send + Sync + 'static {
        async fn get_stats(
            &self,
            request: tonic::Request<super::GetStatsRequest>,
        ) -> Result<tonic::Response<super::GetStatsResponse>, tonic::Status>;
    }
    #[derive(Debug)]
    pub struct StatsServiceServer<T: StatsService> {
        inner: _Inner<T>,
        accept_compression_encodings: (),
        send_compression_encodings: (),
    }
    struct _Inner<T>(Arc<T>);
    impl<T: StatsService> StatsServiceServer<T> {
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        pub fn from_arc(inner: Arc<T>) -> Self {
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
            }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for StatsServiceServer<T>
    where
        T: StatsService,
        B: Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/v2ray_rust_api.StatsService/GetStats" => {
                    #[allow(non_camel_case_types)]
                    struct GetStatsSvc<T: StatsService>(pub Arc<T>);
                    impl<
                        T: StatsService,
                    > tonic::server::UnaryService<super::GetStatsRequest>
                    for GetStatsSvc<T> {
                        type Response = super::GetStatsResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GetStatsRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).get_stats(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetStatsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => {
                    Box::pin(async move {
                        Ok(
                            http::Response::builder()
                                .status(200)
                                .header("grpc-status", "12")
                                .header("content-type", "application/grpc")
                                .body(empty_body())
                                .unwrap(),
                        )
                    })
                }
            }
        }
    }
    impl<T: StatsService> Clone for StatsServiceServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
            }
        }
    }
    impl<T: StatsService> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: StatsService> tonic::transport::NamedService for StatsServiceServer<T> {
        const NAME: &'static str = "v2ray_rust_api.StatsService";
    }
}
