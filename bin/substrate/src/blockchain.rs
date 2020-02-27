// TODO: replace block_on with ThreadPool + channel (we can't use async everywhere :/)

use std::{
	collections::BTreeSet,
	ops::Range,
	sync::Arc,
};
use log::error;
use codec::Encode;
use parking_lot::Mutex;
use parity_secretstore_primitives::{
	Address, KeyServerId, ServerKeyId,
	key_server_set::KeyServerSet,
	requester::Requester,
	service::ServiceTask,
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
	best_block_hash: Mutex<Option<crate::runtime::BlockHash>>,
}

/// Substrate runtime event wrapper.
#[derive(Debug)]
pub enum SubstrateServiceTaskWrapper {
	Event(crate::runtime::Event),
	Task(ss_primitives::service::ServiceTask),
}

impl SecretStoreBlockchain {
	///
	pub fn new(
		client: Client,
		key_server_set: Arc<OnChainKeyServerSet>,
	) -> SecretStoreBlockchain {
		SecretStoreBlockchain {
			client,
			key_server_set,
			best_block_hash: Mutex::new(None),
		}
	}

	///
	pub fn set_best_block(&self, best_block_hash: crate::runtime::BlockHash) {
		*self.best_block_hash.lock() = Some(best_block_hash);
	}

	/// Read pending tasks.
	fn pending_tasks(
		&self,
		block_hash: crate::runtime::BlockHash,
		method: &'static str,
		range: Range<usize>,
	) -> Result<Vec<SubstrateServiceTaskWrapper>, String> {
		let tasks: Vec<ss_primitives::service::ServiceTask> = futures::executor::block_on(async {
			self.client.call_runtime_method(
				block_hash,
				method,
				serialize_range(range),
			).await
		}).map_err(|error| format!("{:?}", error))?;
		Ok(tasks
			.into_iter()
			.map(|task| SubstrateServiceTaskWrapper::Task(task))
			.collect())
	}

	/// Is response required?
	fn is_response_required(
		&self,
		method: &'static str,
		arguments: Vec<u8>,
	) -> Result<bool, String> {
		let best_block_hash = self.best_block_hash.lock().clone().ok_or_else(|| "Best block is unknown")?;

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
	type Event = SubstrateServiceTaskWrapper;
	type BlockEvents = Vec<SubstrateServiceTaskWrapper>;
	type PendingEvents = Vec<SubstrateServiceTaskWrapper>;

	fn block_events(&self, block_hash: Self::BlockHash) -> Self::BlockEvents {
		let events = futures::executor::block_on(
			self.client.header_events(block_hash)
		);

		match events {
			Ok(events) => events
				.into_iter()
				.map(|event| SubstrateServiceTaskWrapper::Event(event.event))
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
			(key_server_id, key_id).encode(),
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
			(key_server_id, key_id).encode(),
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
			(key_server_id, key_id).encode(),
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
			(key_server_id, key_id, requester).encode(),
		)
	}
}

impl MaybeSecretStoreEvent for SubstrateServiceTaskWrapper {
	fn as_secret_store_event(self) -> Option<BlockchainServiceTask> {
		let origin = Default::default();

		match self {
			SubstrateServiceTaskWrapper::Event(
				crate::runtime::Event::substrate_secret_store_runtime(
					substrate_secret_store_runtime::Event::ServerKeyGenerationRequested(
						key_id, requester_address, threshold,
					),
				)
			) => Some(BlockchainServiceTask::Regular(
				origin,
				ServiceTask::GenerateServerKey(
					key_id, Requester::Address(requester_address), threshold as usize,
				)
			)),
			SubstrateServiceTaskWrapper::Task(
				ss_primitives::service::ServiceTask::GenerateServerKey(
					key_id, requester_address, threshold,
				)
			) => Some(BlockchainServiceTask::Regular(
				origin,
				ServiceTask::GenerateServerKey(
					key_id, Requester::Address(requester_address), threshold as usize,
				)
			)),
			SubstrateServiceTaskWrapper::Event(
				crate::runtime::Event::substrate_secret_store_runtime(
					substrate_secret_store_runtime::Event::ServerKeyRetrievalRequested(
						key_id,
					),
				)
			) => Some(BlockchainServiceTask::Regular(
				origin,
				ServiceTask::RetrieveServerKey(
					key_id, None,
				)
			)),
			SubstrateServiceTaskWrapper::Task(
				ss_primitives::service::ServiceTask::RetrieveServerKey(
					key_id,
				)
			) => Some(BlockchainServiceTask::Regular(
				origin,
				ServiceTask::RetrieveServerKey(
					key_id, None,
				)
			)),
			SubstrateServiceTaskWrapper::Event(
				crate::runtime::Event::substrate_secret_store_runtime(
					substrate_secret_store_runtime::Event::DocumentKeyStoreRequested(
						key_id, author, common_point, encrypted_point,
					),
				)
			) => Some(BlockchainServiceTask::Regular(
				origin,
				ServiceTask::StoreDocumentKey(
					key_id, Requester::Address(author), common_point, encrypted_point,
				)
			)),
			SubstrateServiceTaskWrapper::Task(
				ss_primitives::service::ServiceTask::StoreDocumentKey(
					key_id, author, common_point, encrypted_point,
				)
			) => Some(BlockchainServiceTask::Regular(
				origin,
				ServiceTask::StoreDocumentKey(
					key_id, Requester::Address(author), common_point, encrypted_point,
				)
			)),
			SubstrateServiceTaskWrapper::Event(
				crate::runtime::Event::substrate_secret_store_runtime(
					substrate_secret_store_runtime::Event::DocumentKeyShadowRetrievalRequested(
						key_id, requester_address,
					),
				)
			) => Some(BlockchainServiceTask::RetrieveShadowDocumentKeyCommon(
				origin,
				key_id,
				Requester::Address(requester_address),
			)),
			SubstrateServiceTaskWrapper::Task(
				ss_primitives::service::ServiceTask::RetrieveShadowDocumentKeyCommon(
					key_id, requester_address,
				)
			) => Some(BlockchainServiceTask::RetrieveShadowDocumentKeyCommon(
				origin,
				key_id,
				Requester::Address(requester_address),
			)),
			SubstrateServiceTaskWrapper::Event(
				crate::runtime::Event::substrate_secret_store_runtime(
					substrate_secret_store_runtime::Event::DocumentKeyPersonalRetrievalRequested(
						key_id, requester_public,
					),
				)
			) => Some(BlockchainServiceTask::RetrieveShadowDocumentKeyPersonal(
				origin,
				key_id,
				Requester::Public(requester_public),
			)),
			SubstrateServiceTaskWrapper::Task(
				ss_primitives::service::ServiceTask::RetrieveShadowDocumentKeyPersonal(
					key_id, requester_public,
				)
			) => Some(BlockchainServiceTask::RetrieveShadowDocumentKeyPersonal(
				origin,
				key_id,
				Requester::Public(requester_public),
			)),
			_ => None,
		}
	}
}

fn serialize_range(range: Range<usize>) -> Vec<u8> {
	(range.start as u32, range.end as u32).encode()
}
