use std::{net::IpAddr, sync::Arc};

use axum::{Router, routing::any, extract::{Host, State}, response::Redirect};
use axum_server::tls_rustls::RustlsConfig;
use http::{Request, Response, Version, Uri, uri::Scheme, StatusCode};
use hyper::{Body, Client};
use serde::Deserialize;


async fn proxy(mut req: Request<Body>, port: u16) -> Response<Body> {
    let val = format!("0.0.0.0:{port}");
    let mut parts = req.uri().clone().into_parts();
    // Unwrap is safe as it is correctly formatted per two lines above.
    parts.authority = Some(val.parse().unwrap());
    parts.scheme = Some(Scheme::HTTP);
    // Unwrap is safe as we onlt changed athority and scheme both of which are valid.
    *req.uri_mut() = Uri::from_parts(parts).unwrap();
    *req.version_mut() = Version::HTTP_11;
    let client = Client::default();
    client.request(req).await
        .unwrap_or(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            // This unwrap should be safe as it is a valid response
            .body(Body::empty()).unwrap())
}

async fn handler(Host(host): Host, State(redirect_rules): State<Arc<Vec<RedirectRule>>>, req: Request<Body>) -> Response<Body> {
    for rule in &*redirect_rules {
        if host == rule.host_name {
            return proxy(req, rule.port).await;
        }
    }
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::empty())
        .expect("valid 404")
}

#[derive(Deserialize, Clone)]
struct Config {
    ip: IpAddr,
    http_port: u16,
    https_port: u16,
    ssl_cert: String,
    ssl_key: String,
    proxy_path: Option<String>,
    wsgi_path: Option<String>,
}

struct RedirectRule {
    host_name: String,
    port: u16
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args();
    let config: Config = match args.nth(1) {
        Some(config) => match std::fs::read_to_string(&config) {
            Ok(config) => match toml::from_str(&config) {
                Ok(config) => config,
                Err(e) => panic!("Could not parse toml due to: {e}"),
            },
            Err(e) => panic!("Could not open config file due to: {e}"),
        },
        None => panic!("No config supplied")
    };

    tokio::spawn(https_redirect(config.clone()));

    let mut redirect_rules = Vec::new();

    if let Some(path) = config.proxy_path {
        load_proxy_config(&path, &mut redirect_rules);
    }

    if let Some(path) = config.wsgi_path {
        load_wsig_config(&path, &mut redirect_rules, 9300);
    }

    let app = Router::new()
        .route("/", any(handler))
        .route("/*path", any(handler))
        .with_state(Arc::new(redirect_rules));

    let cert = std::fs::read(&config.ssl_cert).expect("Certificate path is invalid");
    let key = std::fs::read(&config.ssl_key).expect("Key path is invalid");

    let tls_config = RustlsConfig::from_pem(cert, key).await.expect("Certificates are invalid");

    let socket_addr = (config.ip, config.https_port);
    axum_server::bind_rustls(socket_addr.into(), tls_config)
        .serve(app.into_make_service())
        .await
        .expect("HTTPS port is in use");
}

async fn redirect(host: String, req: Request<Body>, http_port: u16, https_port: u16) -> Redirect {
    let mut uri = req.uri().clone().into_parts();
    // As long as we do not have numbers in our hostnames this should correctly change the port and
    // thus the new uri is valid. Although it is suspisous that host includes port for HTTP but not
    // for HTTPS.
    uri.authority = Some(host.replace(&http_port.to_string(), &https_port.to_string()).parse().unwrap());
    uri.scheme = Some(Scheme::HTTPS);
    // Unwrap is safe as the new scheme and authority are valid.
    dbg!(Redirect::permanent(&Uri::from_parts(uri).unwrap().to_string()))
}

async fn https_redirect(config: Config) {
    let app = Router::new()
        .route("/", any(move |Host(host): Host, req| redirect(host, req, config.http_port, config.https_port)))
        .route("/*path", any(move |Host(host): Host, req| redirect(host, req, config.http_port, config.https_port)));

    let socket_addr = (config.ip, config.http_port);
    axum_server::bind(socket_addr.into())
        .serve(app.into_make_service())
        .await
        .expect("HTTP port is in use");
}

#[derive(Deserialize)]
struct Proxy {
    cmd: Option<String>,
    port: u16,
}


fn load_proxy_config(path: &str, redirect_rules: &mut Vec<RedirectRule>) {
    let dir = std::fs::read_dir(path).expect("Unable to read proxy path");
    for file in dir {
        let file = file.expect("Unable to read file in proxy dir");
        let content = std::fs::read_to_string(file.path()).expect("Unable to read file contents in proxy path");
        let toml: Proxy = match toml::from_str(&content) {
            Ok(toml) => toml,
            Err(e) => panic!("Unable to parse proxy toml for file: {:?}. Error: {e}", file.path()),
        };
        let host_name = file.path().iter().last().unwrap().to_str().unwrap().to_string();
        redirect_rules.push(RedirectRule { host_name, port: toml.port });
        if let Some(cmd) = toml.cmd {
            let mut iter = cmd.split_whitespace();
            let program = iter.next().expect("No program in prxoxy cmd");
            std::process::Command::new(program)
                .args(iter)
                .spawn()
                .expect("Proxy cmd invalid");
        } 
    }
}

#[derive(Deserialize)]
struct Wsgi {
    file: String,
}

fn load_wsig_config(path: &str, redirect_rules: &mut Vec<RedirectRule>, mut start_port: u16) {
    let dir = std::fs::read_dir(path).expect("Unable to read proxy path");
    for file in dir {
        let file = file.expect("Unable to read file in proxy dir");
        let content = std::fs::read_to_string(file.path()).expect("Unable to read file contents in proxy path");
        let toml: Wsgi = match toml::from_str(&content) {
            Ok(toml) => toml,
            Err(e) => panic!("Unable to parse proxy toml for file: {:?}. Error: {e}", file.path()),
        };
        let host_name = file.path().iter().last().unwrap().to_str().unwrap().to_string();
        redirect_rules.push(RedirectRule { host_name, port: start_port });
        std::process::Command::new("uwsgi")
            .arg("--http")
            .arg(format!(":{start_port}"))
            .arg("--wsgi-file")
            .arg(toml.file)
            .spawn()
            .expect("Uwsgi error, maybe invalid wsgi path");
        start_port += 1;
    }

}
