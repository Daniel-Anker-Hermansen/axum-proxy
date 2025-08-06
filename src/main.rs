use std::{io::Write as _, net::IpAddr, sync::Arc};

use ::http::{Method, Request, Response, StatusCode, Uri, Version, uri::Scheme};
use acme_lib::{Account, persist::FilePersist};
use axum::{body::Body, extract::State, routing::any};
use axum_extra::extract::Host;
use axum_server::tls_rustls::RustlsConfig;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use rustls::crypto::ring;
use serde::Deserialize;

mod acme;
mod http;

async fn serve_folder(
	folder_path: &str,
	req: Request<Body>,
	prefix_len: Option<usize>,
) -> Response<Body> {
	if req.method() != &Method::GET {
		Response::builder()
			.status(StatusCode::NOT_FOUND)
			.header("content-type", "text/plain")
			.body(Body::empty())
			.expect("valid 404")
	} else {
		let parts = req.uri().clone().into_parts();
		let prefix_len = prefix_len.unwrap_or(1);
		// Unwrap is safe because it must have matched a prefix to get here.
		let path = parts.path_and_query.as_ref().unwrap().as_str();
		let new_path = &path[prefix_len..];
		let file_path = format!("{folder_path}/{new_path}");
		let file_path_index = if new_path.is_empty() {
			format!("{folder_path}/index.html")
		} else {
			format!("{folder_path}/{new_path}/index.html")
		};
		let mut contents = tokio::fs::read(&file_path).await;
		contents = match contents {
			Ok(v) => Ok(v),
			Err(_) => tokio::fs::read(&file_path_index).await,
		};
		let guess = mime_guess::from_path(&file_path).first();
		let mime = guess
			.as_ref()
			.map(|e| e.essence_str())
			.unwrap_or(mime_guess::mime::TEXT.as_str());
		if file_path.contains("..") {
			return Response::builder()
				.status(StatusCode::NOT_FOUND)
				.body(Body::empty())
				.expect("valid 404");
		}
		match contents {
			Ok(contents) => Response::builder()
				.status(StatusCode::OK)
				.header("content-type", mime)
				.body(Body::from(contents))
				.expect("valid 200"),
			Err(_) => Response::builder()
				.status(StatusCode::NOT_FOUND)
				.body(Body::empty())
				.expect("valid 404"),
		}
	}
}

async fn proxy(mut req: Request<Body>, port: u16, prefix_len: Option<usize>) -> Response<Body> {
	let val = format!("0.0.0.0:{port}");
	let mut parts = req.uri().clone().into_parts();
	// Unwrap is safe as it is correctly formatted per two lines above.
	parts.authority = Some(val.parse().unwrap());
	parts.scheme = Some(Scheme::HTTP);
	if let Some(prefix_len) = prefix_len {
		// Unwrap is safe because it must have matched a prefix to get here.
		let path = parts.path_and_query.as_ref().unwrap().as_str();
		let new_path = &path[prefix_len..];
		parts.path_and_query = Some(new_path.parse().expect("This is a correct path"));
	}
	parts.path_and_query.as_ref().map(|e| e.path());
	// Unwrap is safe as we onlt changed athority and scheme both of which are valid.
	*req.uri_mut() = Uri::from_parts(parts).unwrap();
	*req.version_mut() = Version::HTTP_11;
	let client = Client::builder(TokioExecutor::new()).build_http();
	client
		.request(req)
		.await
		.map(|res| res.map(|body| Body::new(body)))
		.unwrap_or(
			Response::builder()
				.status(StatusCode::INTERNAL_SERVER_ERROR)
				// This unwrap should be safe as it is a valid response
				.body(Body::empty())
				.unwrap(),
		)
}

async fn handler(
	Host(host): Host,
	State(redirect_rules): State<Arc<Vec<RedirectRule>>>,
	req: Request<Body>,
) -> Response<Body> {
	for rule in &*redirect_rules {
		let path = req.uri().path();
		let rpath = rule.get_path();
		let correct_path = match (path, &rpath) {
			("", Some(_)) => false,
			(path, Some(rule_path)) => path.starts_with(rule_path),
			_ => true,
		};
		// +1 because of slash being included in parts;
		let prefix_len = rpath.as_ref().map(|path| path.len() + 1);
		match rule {
			RedirectRule::Proxy {
				host_name, port, ..
			} => {
				if host == *host_name && correct_path {
					return proxy(req, *port, prefix_len).await;
				}
			}
			RedirectRule::Folder {
				host_name,
				folder_path,
				..
			} => {
				if host == *host_name && correct_path {
					return serve_folder(folder_path, req, prefix_len).await;
				}
			}
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
	email: String,
	domains: Vec<String>,
	proxy_path: Option<String>,
	wsgi_path: Option<String>,
	static_path: Option<String>,
}

enum RedirectRule {
	Proxy {
		host_name: String,
		path: Option<String>,
		port: u16,
	},
	Folder {
		host_name: String,
		folder_path: String,
		path: Option<String>,
	},
}

impl RedirectRule {
	fn get_path(&self) -> &Option<String> {
		match self {
			RedirectRule::Proxy { path, .. } => path,
			RedirectRule::Folder { path, .. } => path,
		}
	}
}

#[tokio::main]
async fn main() {
	ring::default_provider().install_default().unwrap();

	let mut args = std::env::args();
	let config: Config = match args.nth(1) {
		Some(config) => match std::fs::read_to_string(&config) {
			Ok(config) => match toml::from_str(&config) {
				Ok(config) => config,
				Err(e) => panic!("Could not parse toml due to: {e}"),
			},
			Err(e) => panic!("Could not open config file due to: {e}"),
		},
		None => panic!("No config supplied"),
	};

	// We need to spawn the http server before requesting certificates as the challenge needs
	// it to be running
	tokio::spawn(http::http_server(config.clone()));

	let mut account = acme::account(&config.email).unwrap();
	let domains: Vec<&str> = config.domains.iter().map(String::as_str).collect();
	let certificate = acme::get_certificate(&mut account, &domains).await.unwrap();

	let mut redirect_rules = Vec::new();

	if let Some(path) = &config.proxy_path {
		load_proxy_config(path, &mut redirect_rules);
	}

	if let Some(path) = &config.wsgi_path {
		load_wsgi_config(path, &mut redirect_rules, 9300);
	}

	if let Some(path) = &config.static_path {
		load_static_config(path, &mut redirect_rules);
	}

	let app = any(handler).with_state(Arc::new(redirect_rules));

	let cert = certificate.certificate().as_bytes().to_vec();
	let key = certificate.private_key().as_bytes().to_vec();
	let tls_config = RustlsConfig::from_pem(cert, key)
		.await
		.expect("Certificates are invalid");

	let socket_addr = (config.ip, config.https_port);
	let reload = reload_keys(tls_config.clone(), &config, &mut account);
	let server = async {
		axum_server::bind_rustls(socket_addr.into(), tls_config)
			.serve(app.into_make_service())
			.await
			.expect("HTTPS port is in use");
	};

	async {
		tokio::join!(server, reload);
	}
	.await
}

async fn reload_keys(
	tls_config: RustlsConfig,
	config: &Config,
	account: &mut Account<FilePersist>,
) {
	let domains: Vec<&str> = config.domains.iter().map(String::as_str).collect();
	loop {
		let certificate = match acme::get_certificate(account, &domains).await {
			Ok(certificates) => certificates,
			Err(err) => {
				if let Ok(mut file) = std::fs::OpenOptions::new()
					.write(true)
					.create(true)
					.truncate(true)
					.open("/axum-certificate-log")
				{
					// Write the error
					let _ = writeln!(&mut file, "{err}");
				}
				// Retry in 12 hours.
				tokio::time::sleep(std::time::Duration::from_secs(12 * 60 * 60)).await;
				continue;
			}
		};
		let cert = certificate.certificate().as_bytes().to_vec();
		let key = certificate.private_key().as_bytes().to_vec();
		tls_config.reload_from_pem(cert, key).await.unwrap();
		tokio::time::sleep(std::time::Duration::from_secs(
			(certificate.valid_days_left() - 30) as u64 * 24 * 60 * 60,
		))
		.await;
	}
}

#[derive(Deserialize)]
struct Proxy {
	cmd: Option<String>,
	host: String,
	path: Option<String>,
	port: u16,
}

fn load_proxy_config(path: &str, redirect_rules: &mut Vec<RedirectRule>) {
	let dir = std::fs::read_dir(path).expect("Unable to read proxy path");
	for file in dir {
		let file = file.expect("Unable to read file in proxy dir");
		let content = std::fs::read_to_string(file.path())
			.expect("Unable to read file contents in proxy path");
		let toml: Proxy = match toml::from_str(&content) {
			Ok(toml) => toml,
			Err(e) => panic!(
				"Unable to parse proxy toml for file: {:?}. Error: {e}",
				file.path()
			),
		};
		redirect_rules.push(RedirectRule::Proxy {
			host_name: toml.host,
			port: toml.port,
			path: toml.path,
		});
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
	path: Option<String>,
	host: String,
	file: String,
}

fn load_wsgi_config(path: &str, redirect_rules: &mut Vec<RedirectRule>, mut start_port: u16) {
	let dir = std::fs::read_dir(path).expect("Unable to read proxy path");
	for file in dir {
		let file = file.expect("Unable to read file in proxy dir");
		let content = std::fs::read_to_string(file.path())
			.expect("Unable to read file contents in proxy path");
		let toml: Wsgi = match toml::from_str(&content) {
			Ok(toml) => toml,
			Err(e) => panic!(
				"Unable to parse proxy toml for file: {:?}. Error: {e}",
				file.path()
			),
		};
		redirect_rules.push(RedirectRule::Proxy {
			host_name: toml.host,
			port: start_port,
			path: toml.path,
		});
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

#[derive(Deserialize)]
struct Static {
	path: Option<String>,
	host: String,
	file_path: String,
}

fn load_static_config(path: &str, redirect_rules: &mut Vec<RedirectRule>) {
	let dir = std::fs::read_dir(path).expect("Unable to read proxy path");
	for file in dir {
		let file = file.expect("Unable to read file in proxy dir");
		let content = std::fs::read_to_string(file.path())
			.expect("Unable to read file contents in proxy path");
		let toml: Static = match toml::from_str(&content) {
			Ok(toml) => toml,
			Err(e) => panic!(
				"Unable to parse proxy toml for file: {:?}. Error: {e}",
				file.path()
			),
		};
		redirect_rules.push(RedirectRule::Folder {
			host_name: toml.host,
			path: toml.path,
			folder_path: toml.file_path,
		});
	}
}
