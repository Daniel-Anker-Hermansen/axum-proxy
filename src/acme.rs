use std::collections::BTreeMap;

use acme_lib::{
	Account, Certificate, Directory, DirectoryUrl, create_p256_key, persist::FilePersist,
};
use tokio::sync::Mutex;

static ACME_FILES: Mutex<BTreeMap<String, String>> = Mutex::const_new(BTreeMap::new());

pub async fn insert_acme(token: String, proof: String) {
	ACME_FILES.lock().await.insert(token, proof);
}

pub async fn remove_acme(token: &str) {
	ACME_FILES.lock().await.remove(token);
}

pub async fn get_acme(token: &str) -> Option<String> {
	ACME_FILES.lock().await.get(token).cloned()
}

pub fn account(email: &str) -> acme_lib::Result<Account<FilePersist>> {
	let url = DirectoryUrl::LetsEncrypt;
	let persistent = FilePersist::new("/root/axum_proxy/certificates/");
	let dir = Directory::from_url(persistent, url)?;
	dir.account(email)
}

pub async fn get_certificate(
	account: &mut Account<FilePersist>,
	domains: &[&str],
) -> acme_lib::Result<Certificate> {
	// Unwraps only happen in relation to threading due to blocking api instead of an async
	// api.


	let name = domains[0];
	let alt_names = &domains[1..];
	// Try to find a certificate with good remaining validity
	// TODO: Check that the certificate actually has all the alt names required.
	let certificate = account.certificate(name)?;
	if let Some(certificate) = certificate
		&& certificate.valid_days_left() > 30
	{
		return Ok(certificate);
	}

	// Otherwise request a new ceritificate
	let mut ord_new = account.new_order(name, alt_names)?;
	let ord_csr = loop {
		dbg!("loop");
		if let Some(ord_csr) = ord_new.confirm_validations() {
			break ord_csr;
		}
		let auths = ord_new.authorizations()?;
		for auth in auths.into_iter().filter(|auth| auth.need_challenge()) {
			dbg!(auth.domain_name());
			let chall = auth.http_challenge();
			let token = chall.http_token().to_string();
			let proof = chall.http_proof();
			dbg!(&token);
			insert_acme(token.clone(), proof).await;
			let (tx, rx) = tokio::sync::oneshot::channel();
			let handle = std::thread::spawn(|| {
				tx.send(chall.validate(1000)).unwrap();
			});
			rx.await.unwrap()?;
			handle.join().unwrap();
			dbg!("validated");
			remove_acme(&token).await;
		}
		dbg!("refresh?");
		ord_new.refresh()?;
	};
	dbg!("out of loop");
	let pkey_pri = create_p256_key();
	let (tx, rx) = tokio::sync::oneshot::channel();
	let handle = std::thread::spawn(|| {
		assert!(tx.send(ord_csr.finalize_pkey(pkey_pri, 1000)).is_ok());
	});
	dbg!("finalized");
	let ord_cert = rx.await.unwrap()?;
	handle.join().unwrap();
	let cert = ord_cert.download_and_save_cert()?;
	Ok(cert)
}
