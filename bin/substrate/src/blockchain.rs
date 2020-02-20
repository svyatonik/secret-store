// TODO: replace block_on with ThreadPool + channel (we can't use async everywhere :/)

use std::{
	collections::BTreeSet,
	ops::Range,
	sync::Arc,
};
use log::error;
use codec::Encode;
use parity_secretstore_primitives::{
	Address, KeyServerId, ServerKeyId,
	key_server_set::KeyServerSet,
};
use parity_secretstore_substrate_service::{
	Blockchain, BlockchainServiceTask, MaybeSecretStoreEvent,
};
use crate::{
	key_server_set::OnChainKeyServerSet,
	substrate_client::Client,
};

/// Substrate-based blockhain that runs SecretStore module.
pub struct SecretStoreBlockchain {
	/// RPC client that can call RPC on full (presumably archive node) that
	/// is synching the blockhain.
	client: Client,
	/// On-chain key server set.
	key_server_set: Arc<OnChainKeyServerSet>,
	/// Best known block.
	best_block_hash: Option<crate::runtime::BlockHash>,
}

/// Runtime event wrapper.
pub struct SecretStoreEvent(crate::runtime::Event);

impl SecretStoreBlockchain {
	///
	pub fn new(
		client: Client,
		key_server_set: Arc<OnChainKeyServerSet>,
	) -> SecretStoreBlockchain {
		SecretStoreBlockchain {
			client,
			key_server_set,
			best_block_hash: None,
		}
	}

	/// Read pending tasks.
	fn pending_tasks(
		&self,
		block_hash: crate::runtime::BlockHash,
		method: &'static str,
		range: Range<usize>,
	) -> Result<Vec<SecretStoreEvent>, String> {
		let events: Vec<substrate_secret_store_runtime::Event> = futures::executor::block_on(async {
			self.client.call_runtime_method(
				block_hash,
				method,
				serialize_range(range),
			).await
		}).map_err(|error| format!("{:?}", error))?;
		Ok(events
			.into_iter()
			.map(|event| SecretStoreEvent(crate::runtime::Event::substrate_secret_store_runtime(event)))
			.collect())
	}

	/// Is response required?
	fn is_response_required(
		&self,
		method: &'static str,
		arguments: Vec<u8>,
	) -> Result<bool, String> {
		let best_block_hash = self.best_block_hash.ok_or_else(|| "Best block is unknown")?;

		futures::executor::block_on(async {
			self.client.call_runtime_method(
				best_block_hash,
				method,
				arguments,
			).await
		}).map_err(|error| format!("{:?}", error))
	}
}

impl Blockchain for SecretStoreBlockchain {
	type BlockHash = crate::runtime::BlockHash;
	type Event = SecretStoreEvent;
	type BlockEvents = Vec<SecretStoreEvent>;
	type PendingEvents = Vec<SecretStoreEvent>;

	fn block_events(&self, block_hash: Self::BlockHash) -> Self::BlockEvents {
		let events = futures::executor::block_on(
			self.client.header_events(block_hash)
		);

		match events {
			Ok(events) => events
				.into_iter()
				.map(|event| SecretStoreEvent(event.event))
				.collect(),
			Err(error) => {
				error!(
					target: "secretstore",
					"Failed to read block {} events: {:?}",
					block_hash,
					error,
				);

				return Vec::new();
			}
		}
	}

	fn current_key_servers_set(&self) -> BTreeSet<KeyServerId> {
		self.key_server_set.snapshot().current_set.keys().cloned().collect()
	}

	fn server_key_generation_tasks(
		&self,
		block_hash: Self::BlockHash,
		range: Range<usize>,
	) -> Result<Self::PendingEvents, String> {
		self.pending_tasks(block_hash, "SecretStoreServiceApi_server_key_generation_tasks", range)
	}

	fn is_server_key_generation_response_required(
		&self,
		key_id: ServerKeyId,
		key_server_id: KeyServerId,
	) -> Result<bool, String> {
		self.is_response_required(
			"SecretStoreServiceApi_is_server_key_generation_response_required",
			(key_id, key_server_id).encode(),
		)
	}

	fn server_key_retrieval_tasks(
		&self,
		block_hash: Self::BlockHash,
		range: Range<usize>,
	) -> Result<Self::PendingEvents, String> {
		self.pending_tasks(block_hash, "SecretStoreServiceApi_server_key_retrieval_tasks", range)
	}

	fn is_server_key_retrieval_response_required(
		&self,
		key_id: ServerKeyId,
		key_server_id: KeyServerId,
	) -> Result<bool, String> {
		self.is_response_required(
			"SecretStoreServiceApi_is_server_key_retrieval_response_required",
			(key_id, key_server_id).encode(),
		)
	}

	fn document_key_store_tasks(
		&self,
		block_hash: Self::BlockHash,
		range: Range<usize>,
	) -> Result<Self::PendingEvents, String> {
		self.pending_tasks(block_hash, "SecretStoreServiceApi_document_key_store_tasks", range)
	}

	fn is_document_key_store_response_required(
		&self,
		key_id: ServerKeyId,
		key_server_id: KeyServerId,
	) -> Result<bool, String> {
		self.is_response_required(
			"SecretStoreServiceApi_is_document_key_store_response_required",
			(key_id, key_server_id).encode(),
		)
	}

	fn document_key_shadow_retrieval_tasks(
		&self,
		block_hash: Self::BlockHash,
		range: Range<usize>,
	) -> Result<Self::PendingEvents, String> {
		self.pending_tasks(block_hash, "SecretStoreServiceApi_document_key_shadow_retrieval_tasks", range)
	}

	fn is_document_key_shadow_retrieval_response_required(
		&self,
		key_id: ServerKeyId,
		requester: Address,
		key_server_id: KeyServerId,
	) -> Result<bool, String> {
		self.is_response_required(
			"SecretStoreServiceApi_is_document_key_shadow_retrieval_response_required",
			(key_id, requester, key_server_id).encode(),
		)
	}
}

impl MaybeSecretStoreEvent for SecretStoreEvent {
	fn as_secret_store_event(self) -> Option<BlockchainServiceTask> {
		match self.0 {
//			crate::runtime::Event::substrate_secret_store_runtime(event) => Some(event),
			_ => None,
		}
	}
}

fn serialize_range(range: Range<usize>) -> Vec<u8> {
	unimplemented!()
}
