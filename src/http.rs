use axum::{Router, body::Body, extract::Path, response::Redirect, routing::any};
use axum_extra::extract::Host;
use http::{Request, Response, StatusCode, Uri, uri::Scheme};

use crate::{Config, acme::get_acme};

async fn redirect(host: String, req: Request<Body>, https_port: u16) -> Redirect {
	// TODO: The unwraps should be replaced with an error response.
	let mut uri = req.uri().clone().into_parts();
	if https_port == 443 {
		uri.authority = Some(host.parse().unwrap());
	} else {
		uri.authority = Some(format!("{}:{}", host, https_port).parse().unwrap());
	}
	uri.scheme = Some(Scheme::HTTPS);
	Redirect::permanent(&Uri::from_parts(uri).unwrap().to_string())
}

pub async fn http_server(config: Config) {
	let app = Router::new()
		.route(
			"/.well-known/acme-challenge/{token}",
			any(
				async |Path(token): Path<String>| match get_acme(&token).await {
					Some(file) => Response::builder()
						.status(StatusCode::OK)
						.body(Body::from(file))
						.unwrap(),
					None => Response::builder()
						.status(StatusCode::NOT_FOUND)
						.body(Body::empty())
						.unwrap(),
				},
			),
		)
		.fallback(any(move |Host(host): Host, req| {
			redirect(host, req, config.https_port)
		}));

	let socket_addr = (config.ip, config.http_port);
	axum_server::bind(socket_addr.into())
		.serve(app.into_make_service())
		.await
		.expect("HTTP port is in use");
}
