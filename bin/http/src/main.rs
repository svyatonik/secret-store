// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

use std::sync::Arc;
use futures::{FutureExt, TryFutureExt};
use parity_crypto::publickey::KeyPair;
use key_server::{ClusterConfiguration, KeyServerImpl, NodeAddress};
use primitives::{
	acl_storage::InMemoryPermissiveAclStorage,
	executor::{tokio_runtime, TokioHandle},
	key_server_key_pair::InMemoryKeyServerKeyPair,
	key_server_set::InMemoryKeyServerSet,
	key_storage::InMemoryKeyStorage,
};

fn main() {
	env_logger::Builder::new()
		.parse_filters(match std::env::var("RUST_LOG") {
			Ok(log_filter) => log_filter,
			Err(_) => "secretstore=info,secrestore_net=info".into(),
		}.as_str())
		.init();

	let mut runtime = tokio_runtime().unwrap();
	let executor = runtime.executor();

	(0..3).for_each(move |index| {
		let executor = executor.clone();
		std::thread::spawn(move || {
			let key_server = start_key_server(index, executor.clone());
			if index == 0 {
				executor.spawn_std(
					http_service::start_service(
						"127.0.0.1".into(),
						11_000u16,
						key_server,
						None,
					)
					.map(|_| ())
					.boxed()
				);
			}
		});
	});

	runtime.block_on_std(futures::future::pending::<()>());
}

fn start_key_server(key_server_index: usize, executor: TokioHandle) -> Arc<KeyServerImpl> {
	let key_servers_key_pairs = [
		KeyPair::from_secret_slice(&[1u8; 32]).unwrap(),
		KeyPair::from_secret_slice(&[2u8; 32]).unwrap(),
		KeyPair::from_secret_slice(&[3u8; 32]).unwrap(),
	];

	let key_server_key_pair = Arc::new(InMemoryKeyServerKeyPair::new(key_servers_key_pairs[key_server_index].clone()));
	let key_server_config = ClusterConfiguration {
		listener_address: NodeAddress {
			address: "127.0.0.1".into(),
			port: 10_000u16 + key_server_index as u16,
		},
		allow_connecting_to_higher_nodes: true,
		admin_address: None,
		auto_migrate_enabled: false,
	};
	let acl_storage = Arc::new(InMemoryPermissiveAclStorage::default());
	let key_server_set = Arc::new(InMemoryKeyServerSet::new(
		false,
		key_servers_key_pairs
			.iter()
			.enumerate()
			.map(|(index, kp)| (
				kp.address(),
				format!("127.0.0.1:{}", 10_000u16 + index as u16).parse().unwrap(),
			))
			.collect(),
	));
	let key_storage = Arc::new(InMemoryKeyStorage::default());

	key_server::Builder::new()
		.with_self_key_pair(key_server_key_pair.clone())
		.with_acl_storage(acl_storage)
		.with_key_storage(key_storage)
		.with_config(key_server_config)
		.build_for_tcp(
			executor,
			key_server::network::tcp::TcpConfiguration {
				listener_address: key_server::network::tcp::NodeAddress {
					address: "127.0.0.1".into(),
					port: 10_000u16 + key_server_index as u16,
				},
				self_key_pair: key_server_key_pair.clone(),
			},
			key_server_set,
		)
		.unwrap()
}
