use std::collections::HashMap;
use sp_core::H256;
use parking_lot::RwLock;
use parity_secretstore_primitives::KeyServerId;
use parity_secretstore_substrate_service::{
	TransactionPool, SecretStoreCall,
};
use crate::{
	runtime::{TransactionHash},
	substrate_client::Client,
};

///
pub struct SecretStoreTransactionPool {
	client: Client,
	best_block: RwLock<Option<(u32, H256)>>,
	sync_futures_pool: futures::executor::ThreadPool,
}

impl SecretStoreTransactionPool {
	////
	pub fn new(client: Client, sync_futures_pool: futures::executor::ThreadPool) -> SecretStoreTransactionPool {
		SecretStoreTransactionPool {
			client,
			best_block: RwLock::new(None),
			sync_futures_pool,
		}
	}

	pub fn set_best_block(&self, best_block: (u32, H256)) {
		*self.best_block.write() = Some(best_block);
	}
}

impl TransactionPool for SecretStoreTransactionPool {
	type TransactionHash = TransactionHash;

	fn submit_transaction(&self, call: SecretStoreCall) -> Result<Self::TransactionHash, String> {
		let submit_transaction = self.client.submit_transaction(crate::runtime::Call::SecretStore(
			match call {
				SecretStoreCall::ServerKeyGenerated(key_id, key) =>
					node_runtime::SecretStoreCall::server_key_generated(
						key_id,
						key,
					),
				SecretStoreCall::ServerKeyGenerationError(key_id) =>
					node_runtime::SecretStoreCall::server_key_generation_error(
						key_id,
					),
				SecretStoreCall::ServerKeyRetrieved(key_id, key, threshold) =>
					node_runtime::SecretStoreCall::server_key_retrieved(
						key_id,
						key,
						threshold,
					),
				SecretStoreCall::ServerKeyRetrievalError(key_id) =>
					node_runtime::SecretStoreCall::server_key_retrieval_error(
						key_id,
					),
				SecretStoreCall::DocumentKeyStored(key_id) =>
					node_runtime::SecretStoreCall::document_key_stored(
						key_id,
					),
				SecretStoreCall::DocumentKeyStoreError(key_id) =>
					node_runtime::SecretStoreCall::document_key_store_error(
						key_id,
					),
				SecretStoreCall::DocumentKeyCommonRetrieved(key_id, requester, common_point, threshold) =>
					node_runtime::SecretStoreCall::document_key_common_retrieved(
						key_id,
						requester,
						common_point,
						threshold,
					),
				SecretStoreCall::DocumentKeyPersonalRetrieved(key_id, requester, participants, decrypted_secret, shadow) => {
					// we're checking confirmation in Latest block, because tx is applied to the latest state
					let best_block = self.best_block.read().clone().ok_or_else(|| String::from("Best block is unknown"))?;
					let current_set_with_indices: Vec<(KeyServerId, u8)> = futures::executor::block_on(async {
						self.client.call_runtime_method(
							best_block.1,
							"SecretStoreKeyServerSetApi_current_set_with_indices",
							Vec::new(),
						).await
					}).map_err(|err| format!("{:?}", err))?;
					let current_set_with_indices = current_set_with_indices.into_iter().collect::<HashMap<_, _>>();

					let mut participants_mask = ss_primitives::KeyServersMask::default();
					for participant in participants {
						let index = current_set_with_indices.get(&participant)
							.ok_or_else(|| format!("Missing index for key server {}", participant))?;
						participants_mask = participants_mask.union(ss_primitives::KeyServersMask::from_index(*index));
					}

					node_runtime::SecretStoreCall::document_key_personal_retrieved(
						key_id,
						requester,
						participants_mask,
						decrypted_secret,
						shadow,
					)
				},
				SecretStoreCall::DocumentKeyShadowRetrievalError(key_id, requester) =>
					node_runtime::SecretStoreCall::document_key_shadow_retrieval_error(
						key_id,
						requester,
					),
			}
		));

		futures::executor::block_on(async {
			submit_transaction.await
		}).map_err(|err| format!("{:?}", err))
	}
}
