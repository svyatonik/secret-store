mod acl_storage;
mod blockchain;
mod key_server_set;
mod runtime;
mod secret_store;
mod service;
mod substrate_client;
mod transaction_pool;

use std::{
	collections::VecDeque,
	io::Write,
	sync::Arc,
};
use futures::future::FutureExt;
use log::error;
use parity_crypto::publickey::{KeyPair, public_to_address};
use parity_secretstore_primitives::{
	KeyServerId,
	executor::tokio_runtime,
	key_server_key_pair::InMemoryKeyServerKeyPair,
};


fn main() {
	initialize();

	let mut local_pool = futures::executor::LocalPool::new();
	local_pool.run_until(async move {
		// we still need tokio 0.1 runtime to run SS :/
		let tokio_runtime = tokio_runtime().unwrap();
		// and since not everything in SS is async, we need an additional
		// futures executor that we'll use to run futures in sync functions
		let thread_pool = futures::executor::ThreadPool::new().unwrap();

		let uri = format!("{}:{}", "localhost", 11011);
		let self_id = KeyServerId::default();
		let client = substrate_client::Client::new(&uri, sp_keyring::AccountKeyring::Alice.pair()).await.unwrap();

		let (best_sender, best_receiver) = futures::channel::mpsc::unbounded();

		let key_server_key_pair = Arc::new(InMemoryKeyServerKeyPair::new(KeyPair::from_secret([1u8; 32].into()).unwrap()));
		let acl_storage = Arc::new(crate::acl_storage::OnChainAclStorage::new(client.clone()));
		let key_server_set = Arc::new(crate::key_server_set::OnChainKeyServerSet::new(
			client.clone(),
			self_id.clone(),
			thread_pool,
		));
		let key_server = (0u16..3u16).map(|index| secret_store::start(
			tokio_runtime.executor(),
			key_server_key_pair.clone(),
			10_000u16 + index,
			acl_storage.clone(),
			key_server_set.clone(),
		).unwrap()).last().unwrap();
		crate::service::start(
			client.clone(),
			tokio_runtime.executor(),
			key_server,
			key_server_set.clone(),
			key_server_key_pair,
			best_receiver,
		).unwrap();

		let mut finalized_headers = VecDeque::new();
		let mut finalized_header_events_retrieval_active = false;

		let mut fut_finalized_headers = client.subscribe_finalized_heads().await.unwrap();
		let fut_finalized_header_events = futures::future::Fuse::terminated();

		futures::pin_mut!(
			fut_finalized_header_events
		);

		loop {
			futures::select! {
				finalized_header = fut_finalized_headers.next().fuse() => {
					let finalized_header_hash = finalized_header.hash();
					finalized_headers.push_back((finalized_header.number, finalized_header_hash));
					acl_storage.set_best_block((finalized_header.number, finalized_header_hash));
					key_server_set.set_best_block((finalized_header.number, finalized_header_hash));
					//service.set_best_block((finalized_header.number, finalized_header_hash));
				},
				finalized_header_events = fut_finalized_header_events => {
					/*match finalized_header_events {
						Ok(finalized_header_events) => service.append_block_events(finalized_header_events),
						Err(error) => error!(
							target: "secretstore_net",
							"Error reading Substrate header events: {:?}",
							error,
						),
					}*/
				},
			}

			if !finalized_header_events_retrieval_active {
				if let Some((_, finalized_header_hash)) = finalized_headers.pop_front() {
					finalized_header_events_retrieval_active = true;
					fut_finalized_header_events.set(client.header_events(finalized_header_hash).fuse());
				}
			}
		}
	});
}

fn initialize() {
	let mut builder = env_logger::Builder::new();

	let filters = match std::env::var("RUST_LOG") {
		Ok(env_filters) => format!("secretstore=info,secretstore_net=info,{}", env_filters),
		Err(_) => "secretstore=info,secretstore_net=info".into(),
	};

	builder.parse_filters(&filters);
	builder.format(move |buf, record| {
		writeln!(buf, "{}", {
			let timestamp = time::strftime("%Y-%m-%d %H:%M:%S %Z", &time::now())
				.expect("Time is incorrectly formatted");
			if cfg!(windows) {
				format!("{} {} {} {}", timestamp, record.level(), record.target(), record.args())
			} else {
				use ansi_term::Colour as Color;
				let log_level = match record.level() {
					log::Level::Error => Color::Fixed(9).bold().paint(record.level().to_string()),
					log::Level::Warn => Color::Fixed(11).bold().paint(record.level().to_string()),
					log::Level::Info => Color::Fixed(10).paint(record.level().to_string()),
					log::Level::Debug => Color::Fixed(14).paint(record.level().to_string()),
					log::Level::Trace => Color::Fixed(12).paint(record.level().to_string()),
				};
				format!("{} {} {} {}"
					, Color::Fixed(8).bold().paint(timestamp)
					, log_level
					, Color::Fixed(8).paint(record.target())
					, record.args())
			}
		})
	});

	builder.init();
}
