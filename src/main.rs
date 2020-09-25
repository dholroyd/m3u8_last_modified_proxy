use hyper::server::conn::AddrStream;
use hyper::{Body, Request, Response, Server, StatusCode, HeaderMap, Uri, Client, Error};
use hyper::service::{service_fn, make_service_fn};
use std::net::{IpAddr, SocketAddr};
use lazy_static::lazy_static;
use hyper::header::{HeaderValue, InvalidHeaderValue, ToStrError};
use std::str::FromStr;
use hyper::http::uri::InvalidUri;
use std::convert::Infallible;
use structopt::*;
use log::*;
use std::{fs, io, sync};
use rustls::internal::pemfile;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use std::pin::Pin;
use futures_util::{
    future::TryFutureExt,
    stream::{Stream, StreamExt, TryStreamExt},
};
use core::task::{Context, Poll};
use hls_m3u8::parser::Cursor;

#[derive(StructOpt)]
#[structopt(name = "m3u8_last_modified_proxy")]
pub struct Cmd {
    #[structopt(name = "listen-port", long)]
    pub listen_port: u16,

    #[structopt(name = "tls-cert-file", long)]
    pub cert_file: Option<String>,

    #[structopt(name = "tls-key-file", long)]
    pub key_file: Option<String>,

    #[structopt(name = "tls-chain-file", long)]
    pub chain_cert_file: Option<String>,

    #[structopt(name = "base-url", long)]
    pub base_url: String,
}

fn is_hop_header(name: &str) -> bool {
    use unicase::Ascii;

    // A list of the headers, using `unicase` to help us compare without
    // worrying about the case, and `lazy_static!` to prevent reallocation
    // of the vector.
    lazy_static! {
        static ref HOP_HEADERS: Vec<Ascii<&'static str>> = vec![
            Ascii::new("Connection"),
            Ascii::new("Keep-Alive"),
            Ascii::new("Proxy-Authenticate"),
            Ascii::new("Proxy-Authorization"),
            Ascii::new("Te"),
            Ascii::new("Trailers"),
            Ascii::new("Transfer-Encoding"),
            Ascii::new("Upgrade"),
        ];
    }

    HOP_HEADERS.iter().any(|h| h == &name)
}

/// Returns a clone of the headers without the [hop-by-hop headers].
///
/// [hop-by-hop headers]: http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
fn remove_hop_headers(headers: &HeaderMap<HeaderValue>) -> HeaderMap<HeaderValue> {
    let mut result = HeaderMap::new();
    for (k, v) in headers.iter() {
        if !is_hop_header(k.as_str()) {
            result.insert(k.clone(), v.clone());
        }
    }
    result
}

fn create_proxied_response<B>(mut response: Response<B>) -> Response<B> {
    *response.headers_mut() = remove_hop_headers(response.headers());
    response
}

fn forward_uri<B>(forward_url: &str, req: &Request<B>) -> Result<Uri, InvalidUri> {
    let forward_uri = match req.uri().query() {
        Some(query) => format!("{}{}?{}", forward_url, req.uri().path(), query),
        None => format!("{}{}", forward_url, req.uri().path()),
    };

    Uri::from_str(forward_uri.as_str())
}

fn create_proxied_request<B>(
    client_ip: IpAddr,
    forward_url: &str,
    mut request: Request<B>,
) -> Result<Request<B>, ProxyError> {
    *request.headers_mut() = remove_hop_headers(request.headers());
    *request.uri_mut() = forward_uri(forward_url, &request)?;

    let x_forwarded_for_header_name = "x-forwarded-for";

    // Add forwarding information in the headers
    match request.headers_mut().entry(x_forwarded_for_header_name) {
        hyper::header::Entry::Vacant(entry) => {
            entry.insert(client_ip.to_string().parse()?);
        }

        hyper::header::Entry::Occupied(mut entry) => {
            let addr = format!("{}, {}", entry.get().to_str()?, client_ip);
            entry.insert(addr.parse()?);
        }
    }

    Ok(request)
}

#[derive(Debug)]
pub enum ProxyError {
    InvalidUri(InvalidUri),
    HyperError(Error),
    ForwardHeaderError,
}
impl From<Error> for ProxyError {
    fn from(err: Error) -> ProxyError {
        ProxyError::HyperError(err)
    }
}
impl From<InvalidUri> for ProxyError {
    fn from(err: InvalidUri) -> ProxyError {
        ProxyError::InvalidUri(err)
    }
}
impl From<ToStrError> for ProxyError {
    fn from(_err: ToStrError) -> ProxyError {
        ProxyError::ForwardHeaderError
    }
}
impl From<InvalidHeaderValue> for ProxyError {
    fn from(_err: InvalidHeaderValue) -> ProxyError {
        ProxyError::ForwardHeaderError
    }
}

pub async fn call(
    client_ip: IpAddr,
    forward_uri: &str,
    request: Request<Body>,
) -> Result<Response<Body>, ProxyError> {
    let proxied_request = create_proxied_request(client_ip, &forward_uri, request)?;
    info!("Request {:?}", forward_uri);
    let https = hyper_rustls::HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    let response = client.request(proxied_request).await?;
    let proxied_response = create_proxied_response(response);
    Ok(proxied_response)
}

fn find_end_time(media_playlist: &hls_m3u8::MediaPlaylist) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    let mut datetime = None;
    // calculate forward from the last-seen EXT-X-PROGRAM-DATE-TIME through to the end of the
    // segment list, adding durations as we go,
    for (_seq, seg) in &media_playlist.segments {
        if let Some(ref ext_inf) = seg.duration {
            if let Some(ref prog_date_time) = seg.program_date_time {
                datetime = Some(prog_date_time.date_time);
            }
            if let Some(t) = datetime.take() {
                datetime = Some(t + chrono::Duration::from_std(ext_inf.duration()).ok()?);
            }
        }
    }
    datetime
}

async fn handle_playlist(response: Response<Body>) -> Result<Response<Body>, Infallible> {
    let (mut parts, body) = response.into_parts();
    match hyper::body::to_bytes(body).await {
        Ok(data) => {
            let data = data.to_vec();
            let parser = hls_m3u8::parser::Parser::new(Cursor::from(&data[..]));
            match parser.parse() {
                Ok(build) => {
                    if let Ok(pl) = build.build() {
                        if let Some(end) = find_end_time(&pl) {
                            if let Some(orig) = parts.headers.get(hyper::header::LAST_MODIFIED).map(|h| h.clone()) {
                                parts.headers.insert("X-Original-Last-Modified", orig);
                            }
                            // remove any ETag header in the original response so that the
                            // downstream cache is obliged to revalidate only in terms of the
                            // Last-Modified value,
                            parts.headers.remove(hyper::header::ETAG);
                            parts.headers.insert(hyper::header::LAST_MODIFIED, end.to_rfc2822().parse().unwrap());
                        }
                    }
                }
                Err(e) => {
                    debug!("Not handling as Media Playlist: {:?}", e);
                }
            }
            Ok(Response::from_parts(parts, Body::from(data)))
        },
        Err(e) => {
            eprint!("{:?}", e);
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap())
        }
    }


}
async fn handle(client_ip: IpAddr, base_url: String, req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match call(client_ip, &base_url, req).await {
        Ok(response) => {
            if let Some(content_type) = response.headers().get("content-type") {
                if content_type == "application/vnd.apple.mpegurl" {
                    handle_playlist(response).await
                } else {
                    Ok(response)
                }
            } else {
                Ok(response)
            }
        }
        Err(e) => {
            error!("Upstream: {:?}", e);
            Ok(Response::builder()
                              .status(StatusCode::BAD_GATEWAY)
                              .body(Body::empty())
                              .unwrap())
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let cmd = Cmd::from_args();

    if cmd.base_url.ends_with("/") {
        warn!("base-url with trailing slash is probably not what you want {:?}", cmd.base_url);
    }
    let addr = ([0, 0, 0, 0], cmd.listen_port).into();

    if let (Some(cert_file), Some(key_file)) = (cmd.cert_file, cmd.key_file) {
        tls_service(addr, &cert_file, &key_file, cmd.chain_cert_file.as_ref(), &cmd.base_url).await.unwrap()
    } else {
        plain_service(addr, &cmd.base_url).await
    }
}

async fn tls_service(addr: SocketAddr, cert_file: &str, key_file: &str, chain_cert_file: Option<&String>, base_url: &str) -> Result<(), io::Error> {
    let tls_conf = {
        // Load public certificate.
        let mut certs = load_certs(cert_file)?;
        if let Some(chain_cert_file) = chain_cert_file {
            let chain = load_certs(chain_cert_file)?;
            certs.extend_from_slice(&chain[..])
        }
        // Load private key.
        let key = load_private_key(key_file)?;
        // Do not use client certificate authentication.
        let mut cfg = rustls::ServerConfig::new(rustls::NoClientAuth::new());
        // Select a certificate to use.
        cfg.set_single_cert(certs, key)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        // In order to configure ALPN to accept HTTP/2 as well as HTTP/1.1, we need to ensure the
        // request to upstream negotiates HTTP version separately, rather than blindly forwarding
        // an HTTP/2 request that upstream might not accept
        //cfg.set_protocols(&[b"h2".to_vec(), b"http/1.1".to_vec()]);
        sync::Arc::new(cfg)
    };

    let mut tcp = TcpListener::bind(&addr).await?;
    let tls_acceptor = TlsAcceptor::from(tls_conf);

    let incoming_tls_stream = tcp
        .incoming()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Incoming failed: {:?}", e)))
        .and_then(move |s| {
            tls_acceptor.accept(s).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("TLS Error: {:?}", e))
            })
        })
        .filter(|s| {
            if let Err(e) = s {
                warn!("client-connection error: {:?}", e);
            }
            // ignore errors so that the service doesn't exit
            futures::future::ready(s.is_ok())
        })
        .boxed();

    let service = make_service_fn(move |conn: &TlsStream<TcpStream>| {
        let remote_addr = conn.get_ref().0.peer_addr().unwrap().ip();
        let base_url = base_url.to_owned();
        async move {
            Ok::<_, io::Error>(service_fn(move |req| handle(remote_addr, base_url.clone(), req)))
        }
    });
    let server = Server::builder(HyperAcceptor {
        acceptor: incoming_tls_stream,
    })
        .serve(service);

    // Run the future, keep going until an error occurs.
    println!("Starting to serve on https://{}.", addr);
    server.await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Server failed: {:?}", e)))
}
struct HyperAcceptor<'a> {
    acceptor: Pin<Box<dyn Stream<Item = Result<TlsStream<TcpStream>, io::Error>> + 'a>>,
}
impl hyper::server::accept::Accept for HyperAcceptor<'_> {
    type Conn = TlsStream<TcpStream>;
    type Error = io::Error;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        Pin::new(&mut self.acceptor).poll_next(cx)
    }
}

async fn plain_service(addr: SocketAddr, base_url: &str) {
    let make_svc = make_service_fn(|conn: &AddrStream| {
        let remote_addr = conn.remote_addr().ip();
        let base_url = base_url.to_owned();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| handle(remote_addr, base_url.clone(), req)))
        }
    });

    let server = Server::bind(&addr)
        .serve(make_svc);

    info!("Running server on http://{:?}", addr);

    if let Err(e) = server.await {
        error!("server error: {}", e)
    }
}


// Load public certificate from file.
fn load_certs(filename: &str) -> io::Result<Vec<rustls::Certificate>> {
    // Open certificate file.
    let certfile = fs::File::open(filename)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    pemfile::certs(&mut reader).map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to load certificate".to_string()))
}

// Load private key from file.
fn load_private_key(filename: &str) -> io::Result<rustls::PrivateKey> {
    // Open keyfile.
    let keyfile = fs::File::open(filename)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);

    // Load and return a single private key.
    let keys = pemfile::rsa_private_keys(&mut reader)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, format!("failed to load private key {}", filename)))?;
    if keys.len() != 1 {
        return Err(io::Error::new(io::ErrorKind::Other, "expected a single private key".to_string()));
    }
    Ok(keys[0].clone())
}
