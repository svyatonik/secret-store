use std::{
	collections::BTreeMap,
	net::SocketAddr,
	str::FromStr,
	sync::Arc,
};
use futures::FutureExt;
use log::error;
use parking_lot::RwLock;
use codec::Encode;
use sp_core::H256;
use parity_secretstore_primitives::{
	KeyServerId,
	key_server_set::{KeyServerSet, KeyServerSetSnapshot, KeyServerSetMigration, MigrationId},
	error::Error,
};
use crate::substrate_client::Client;

/// Number of blocks before the same-migration transaction (be it start or confirmation) will be retried.
const TRANSACTION_RETRY_INTERVAL_BLOCKS: u32 = 30;

pub struct OnChainKeyServerSet {
	client: Arc<Client>,
	self_id: KeyServerId,
	sync_futures_pool: futures::executor::ThreadPool,
	data: Arc<RwLock<OnChainKeyServerSetData>>,
}

struct OnChainKeyServerSetData {
	best_block: Option<(u32, H256)>,
	best_block_snapshot: KeyServerSetSnapshot<SocketAddr>,
	/// Previous start migration transaction (if has been sent).
	start_migration_tx: Option<PreviousMigrationTransaction>,
	/// Previous confirm migration transaction (if has been sent).
	confirm_migration_tx: Option<PreviousMigrationTransaction>,
}

struct PreviousMigrationTransaction {
	/// ID of migration process.
	migration_id: MigrationId,
	/// Best block when transaction has been sent.
	block: (u32, H256),
}

impl OnChainKeyServerSet {
	pub fn new(client: Client, self_id: KeyServerId, sync_futures_pool: futures::executor::ThreadPool) -> Self {
		OnChainKeyServerSet {
			client: Arc::new(client),
			self_id,
			sync_futures_pool,
			data: Arc::new(RwLock::new(OnChainKeyServerSetData {
				best_block: None,
				best_block_snapshot: KeyServerSetSnapshot {
					current_set: BTreeMap::new(),
					new_set: BTreeMap::new(),
					migration: None,
				},
				start_migration_tx: None,
				confirm_migration_tx: None,
			})),
		}
	}

	pub fn set_best_block(&self, best_block: (u32, H256)) {
		self.data.write().best_block = Some(best_block);

		let data = self.data.clone();
		let client = self.client.clone();
		let self_id = self.self_id.encode();
		let call_runtime_method = async move {
			client.call_runtime_method(
				best_block.1,
				"SecretStoreKeyServerSetApi_snapshot",
				self_id,
			).await
		};

		self.sync_futures_pool.spawn_ok(
			call_runtime_method.map(move |result: Result<ss_primitives::key_server_set::KeyServerSetSnapshot, _>| {
				match result {
					Ok(snapshot) => {
						let snapshot = KeyServerSetSnapshot {
							current_set: into_socket_addr_set(best_block.1, snapshot.current_set),
							new_set: into_socket_addr_set(best_block.1, snapshot.new_set),
							migration: snapshot.migration.map(|migration| KeyServerSetMigration {
								id: migration.id,
								set: into_socket_addr_set(best_block.1, migration.set),
								master: migration.master,
								is_confirmed: migration.is_confirmed,
							}),
						};
println!("=== new snapshot: {:?}", snapshot);
						data.write().best_block_snapshot = snapshot;
					},
					Err(err) => error!(
						target: "secretstore",
						"Failed to read key server set snapshot at {}: {:?}",
						best_block.1,
						err,
					),
				}

				()
			})
		);
	}
}

impl KeyServerSet for OnChainKeyServerSet {
	type NetworkAddress = SocketAddr;

	fn is_isolated(&self) -> bool {
		!self.data.read().best_block_snapshot.current_set.contains_key(&self.self_id)
	}

	fn snapshot(&self) -> KeyServerSetSnapshot<SocketAddr> {
		self.data.read().best_block_snapshot.clone()
	}

	fn start_migration(&self, migration_id: MigrationId) {
		{
			let mut data = self.data.write();
			let best_block = match data.best_block {
				Some(best_block) => best_block,
				None => return,
			};
			if !update_last_transaction_block(best_block, &migration_id, &mut data.start_migration_tx) {
				return;
			}
		}

		let submit_result = futures::executor::block_on(async {
			self.client.submit_transaction(node_runtime::Call::SecretStore(
				node_runtime::SecretStoreCall::start_migration(
					migration_id,
				),
			)).await
		});

		if let Err(error) = submit_result {
			error!(
				target: "secretstore_net",
				"Error submitting start migration transaction: {:?}",
				error,
			);
		}
	}

	fn confirm_migration(&self, migration_id: MigrationId) {
		{
			let mut data = self.data.write();
			let best_block = match data.best_block {
				Some(best_block) => best_block,
				None => return,
			};
			if !update_last_transaction_block(best_block, &migration_id, &mut data.confirm_migration_tx) {
				return;
			}
		}

		let submit_result = futures::executor::block_on(async {
			self.client.submit_transaction(node_runtime::Call::SecretStore(
				node_runtime::SecretStoreCall::confirm_migration(
					migration_id,
				),
			)).await
		});

		if let Err(error) = submit_result {
			error!(
				target: "secretstore_net",
				"Error submitting confirm migration transaction: {:?}",
				error,
			);
		}
	}
}

fn update_last_transaction_block(
	best_block: (u32, H256),
	migration_id: &MigrationId,
	previous_transaction: &mut Option<PreviousMigrationTransaction>,
) -> bool {
	match previous_transaction.as_ref() {
		// no previous transaction => send immediately
		None => (),
		// previous transaction has been sent for other migration process => send immediately
		Some(tx) if tx.migration_id != *migration_id => (),
		// if we have sent the same type of transaction recently => do nothing (hope it will be mined eventually)
		// if we have sent the same transaction some time ago =>
		//   assume that our tx queue was full
		//   or we didn't have enough eth fot this tx
		//   or the transaction has been removed from the queue (and never reached any miner node)
		// if we have restarted after sending tx => assume we have never sent it
		Some(tx) => {
			if tx.block.0 > best_block.0 || best_block.0 - tx.block.0 < TRANSACTION_RETRY_INTERVAL_BLOCKS {
				return false;
			}
		},
	}

	*previous_transaction = Some(PreviousMigrationTransaction {
		migration_id: migration_id.clone(),
		block: best_block,
	});

	true
}

fn into_socket_addr_set(
	best_block_hash: H256,
	map: Vec<(KeyServerId, Vec<u8>)>,
) -> BTreeMap<KeyServerId, SocketAddr> {
	map.into_iter()
		.filter_map(|(server_id, server_address)| {
			let server_address = parse_socket_addr(server_address);
			match server_address {
				Ok(server_address) => Some((server_id, server_address)),
				Err(err) => {
					error!(
						target: "secretstore",
						"Failed to parse address from server set snapshot at {}: {:?}",
						best_block_hash,
						err,
					);

					None
				}
			}
		})
		.collect()
}

fn parse_socket_addr(
	server_address: Vec<u8>,
) -> Result<SocketAddr, String> {
	String::from_utf8(server_address)
		.map_err(|err| format!("{}", err))
		.and_then(|addr_str| SocketAddr::from_str(&addr_str)
			.map_err(|err| format!("{}", err)))
}
