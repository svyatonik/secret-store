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

use std::collections::BTreeSet;
use std::sync::Arc;
use futures03::{
	compat::Future01CompatExt,
	future::{ready, FutureExt},
};
use parking_lot::Mutex;
use parity_crypto::publickey::public_to_address;
use parity_secretstore_primitives::acl_storage::AclStorage;
use parity_secretstore_primitives::key_storage::KeyStorage;
use crate::key_server_cluster::math;
use crate::types::{Error, Public, Requester, ServerKeyId};
use crate::key_server_cluster::ClusterClient;

/// Secret store key server implementation
pub struct KeyServerImpl {
	data: Arc<Mutex<KeyServerCore>>,
}

/// Secret store key server data.
pub struct KeyServerCore {
	cluster: Arc<dyn ClusterClient>,
	acl_storage: Arc<dyn AclStorage>,
	key_storage: Arc<dyn KeyStorage>,
}

impl KeyServerImpl {
	/// Create new key server instance
	pub fn new(
		cluster: Arc<dyn ClusterClient>,
		acl_storage: Arc<dyn AclStorage>,
		key_storage: Arc<dyn KeyStorage>,
	) -> Result<Self, Error> {
		Ok(KeyServerImpl {
			data: Arc::new(Mutex::new(KeyServerCore::new(cluster, acl_storage, key_storage)?)),
		})
	}

	/// Get cluster client reference.
	pub fn cluster(&self) -> Arc<dyn ClusterClient> {
		self.data.lock().cluster.clone()
	}
}

impl KeyServerCore {
	pub fn new(
		cluster: Arc<dyn ClusterClient>,
		acl_storage: Arc<dyn AclStorage>,
		key_storage: Arc<dyn KeyStorage>,
	) -> Result<Self, Error> {
		Ok(KeyServerCore {
			cluster,
			acl_storage,
			key_storage,
		})
	}
}


impl parity_secretstore_primitives::key_server::KeyServer for KeyServerImpl {
}

impl parity_secretstore_primitives::key_server::ServerKeyGenerator for KeyServerImpl {
	type GenerateKeyFuture = std::pin::Pin<Box<dyn std::future::Future<Output = parity_secretstore_primitives::key_server::ServerKeyGenerationResult> + Send>>;
	type RestoreKeyFuture = std::pin::Pin<Box<dyn std::future::Future<Output = parity_secretstore_primitives::key_server::ServerKeyRetrievalResult> + Send>>;

	fn generate_key(
		&self,
		origin: Option<parity_secretstore_primitives::key_server::Origin>,
		key_id: ServerKeyId,
		author: Requester,
		threshold: usize,
	) -> Self::GenerateKeyFuture {
		let key_server_core = self.data.clone();
		async move {
			let session_result = async move {
				let author_address = author.address(&key_id)?;
				let session = key_server_core
					.lock()
					.cluster
					.new_generation_session(key_id, origin, author_address, threshold)?;
				session.into_wait_future()
					.compat()
					.await
			}.await;

			parity_secretstore_primitives::key_server::SessionResult {
				origin,
				params: parity_secretstore_primitives::key_server::ServerKeyGenerationParams {
					key_id,
				},
				result: session_result.map(|key| parity_secretstore_primitives::key_server::ServerKeyGenerationArtifacts {
					key,
				})
			}
		}.boxed()
	}

	fn restore_key_public(
		&self,
		origin: Option<parity_secretstore_primitives::key_server::Origin>,
		key_id: parity_secretstore_primitives::ServerKeyId,
		requester: Option<Requester>,
	) -> Self::RestoreKeyFuture {
		let key_server_core = self.data.clone();
		async move {
			let session_result = async move {
				let requester_address = match requester {
					Some(requester) => Some(requester.address(&key_id)?),
					None => None,
				};
				let session = key_server_core
					.lock()
					.cluster
					.new_key_version_negotiation_session(key_id)?;
				let session_core = session.session.clone();
				let _ = session
					.into_wait_future()
					.compat()
					.await?;
				session_core
					.common_key_data()
					.and_then(|key_share| {
						let requester_is_author = requester_address
							.map(|requester_address| requester_address == key_share.author)
							// TODO: move this check to services
							// if requester is None, we will return server key unconditionally
							.unwrap_or(true);
						if requester_is_author {
							Ok(key_share)
						} else {
							Err(Error::AccessDenied)
						}
					})
			}.await;

			parity_secretstore_primitives::key_server::SessionResult {
				origin,
				params: parity_secretstore_primitives::key_server::ServerKeyRetrievalParams {
					key_id,
				},
				result: session_result.map(|key_share| parity_secretstore_primitives::key_server::ServerKeyRetrievalArtifacts {
					author: key_share.author,
					key: key_share.public,
					threshold: key_share.threshold,
				})
			}
		}.boxed()
	}
}

impl parity_secretstore_primitives::key_server::DocumentKeyServer for KeyServerImpl {
	type StoreDocumentKeyFuture = std::pin::Pin<Box<dyn std::future::Future<Output = parity_secretstore_primitives::key_server::DocumentKeyStoreResult> + Send>>;
	type GenerateDocumentKeyFuture = std::pin::Pin<Box<dyn std::future::Future<Output = parity_secretstore_primitives::key_server::DocumentKeyGenerationResult> + Send>>;
	type RestoreDocumentKeyFuture = std::pin::Pin<Box<dyn std::future::Future<Output = parity_secretstore_primitives::key_server::DocumentKeyRetrievalResult> + Send>>;
	type RestoreDocumentKeyCommonFuture = std::pin::Pin<Box<dyn std::future::Future<Output = parity_secretstore_primitives::key_server::DocumentKeyCommonRetrievalResult> + Send>>;
	type RestoreDocumentKeyShadowFuture = std::pin::Pin<Box<dyn std::future::Future<Output = parity_secretstore_primitives::key_server::DocumentKeyShadowRetrievalResult> + Send>>;

	fn store_document_key(
		&self,
		origin: Option<parity_secretstore_primitives::key_server::Origin>,
		key_id: ServerKeyId,
		author: Requester,
		common_point: Public,
		encrypted_document_key: Public,
	) -> Self::StoreDocumentKeyFuture {
		let key_server_core = self.data.clone();
		async move {
			let session_result = async move {
				let session = key_server_core
					.lock()
					.cluster
					.new_encryption_session(key_id, author, common_point, encrypted_document_key)?;
				session
					.into_wait_future()
					.compat()
					.await
			}.await;

			parity_secretstore_primitives::key_server::SessionResult {
				origin,
				params: parity_secretstore_primitives::key_server::DocumentKeyStoreParams {
					key_id,
				},
				result: session_result.map(|_| parity_secretstore_primitives::key_server::DocumentKeyStoreArtifacts)
			}
		}.boxed()
	}

	fn generate_document_key(
		&self,
		origin: Option<parity_secretstore_primitives::key_server::Origin>,
		key_id: ServerKeyId,
		author: Requester,
		threshold: usize,
	) -> Self::GenerateDocumentKeyFuture {
		let key_server_core = self.data.clone();
		async move {
			let session_result = async move {
				// recover requestor' public key from signature
				let author_public = author.public(&key_id)?;

				// generate server key
				let session = key_server_core
					.lock()
					.cluster
					.new_generation_session(key_id, origin, public_to_address(&author_public), threshold)?;
				let server_key = session
					.into_wait_future()
					.compat()
					.await?;

				// generate random document key
				let document_key = math::generate_random_point()?;
				let encrypted_document_key = math::encrypt_secret(&document_key, &server_key)?;

				// store document key in the storage
				let session = key_server_core
					.lock()
					.cluster
					.new_encryption_session(
						key_id,
						author,
						encrypted_document_key.common_point,
						encrypted_document_key.encrypted_point,
					)?;
				let _ = session
					.into_wait_future()
					.compat()
					.await?;

				Ok(document_key)
			}.await;

			parity_secretstore_primitives::key_server::SessionResult {
				origin,
				params: parity_secretstore_primitives::key_server::DocumentKeyGenerationParams {
					key_id,
				},
				result: session_result.map(|document_key| parity_secretstore_primitives::key_server::DocumentKeyGenerationArtifacts {
					document_key,
				})
			}
		}.boxed()
	}

	fn restore_document_key(
		&self,
		origin: Option<parity_secretstore_primitives::key_server::Origin>,
		key_id: ServerKeyId,
		requester: Requester,
	) -> Self::RestoreDocumentKeyFuture {
		let key_server_core = self.data.clone();
		async move {
			let requester_copy = requester.clone();
			let session_result = async move {
				let session = key_server_core
					.lock()
					.cluster
					.new_decryption_session(key_id, origin, requester, None, false, false)?;
				session
					.into_wait_future()
					.compat()
					.await
			}.await;

			parity_secretstore_primitives::key_server::SessionResult {
				origin,
				params: parity_secretstore_primitives::key_server::DocumentKeyRetrievalParams {
					key_id,
					requester: requester_copy,
				},
				result: session_result.map(|document_key| parity_secretstore_primitives::key_server::DocumentKeyRetrievalArtifacts {
					document_key: document_key.decrypted_secret,
				})
			}
		}.boxed()
	}

	fn restore_document_key_common(
		&self,
		origin: Option<parity_secretstore_primitives::key_server::Origin>,
		key_id: ServerKeyId,
		requester: Requester,
	) -> Self::RestoreDocumentKeyCommonFuture {
		let acl_storage = self.data.lock().acl_storage.clone();
		let key_storage = self.data.lock().key_storage.clone();
		let prepare_result = || {
			let requester_address = requester.address(&key_id)?;
			let is_allowed = acl_storage.check(requester_address, &key_id)?;
			if !is_allowed {
				return Err(Error::AccessDenied);
			}

			let key_share = key_storage.get(&key_id)
				.and_then(|key_share| key_share.ok_or(Error::ServerKeyIsNotFound))?;
			let common_point = key_share.common_point.ok_or(Error::DocumentKeyIsNotFound)?;
			let common_point = math::make_common_shadow_point(key_share.threshold, common_point)?;
			Ok((key_share.threshold, common_point))
		};
		let session_result = prepare_result();

		ready(parity_secretstore_primitives::key_server::SessionResult {
			origin,
			params: parity_secretstore_primitives::key_server::DocumentKeyCommonRetrievalParams {
				key_id,
				requester,
			},
			result: session_result.map(|(threshold, common_point)| parity_secretstore_primitives::key_server::DocumentKeyCommonRetrievalArtifacts {
				common_point,
				threshold,
			})
		}).boxed()
	}

	fn restore_document_key_shadow(
		&self,
		origin: Option<parity_secretstore_primitives::key_server::Origin>,
		key_id: ServerKeyId,
		requester: Requester,
	) -> Self::RestoreDocumentKeyShadowFuture {
		let key_server_core = self.data.clone();
		async move {
			let requester_copy = requester.clone();
			let session_result = async move {
				let session = key_server_core
					.lock()
					.cluster
					.new_decryption_session(key_id, origin, requester, None, true, false)?;
				let document_key = session
					.into_wait_future()
					.compat()
					.await?;
				Ok((
					0, // TODO: document_key.threshold
					document_key.common_point.ok_or(Error::DocumentKeyIsNotFound)?,
					document_key.decrypted_secret,
				))
			}.await;

			parity_secretstore_primitives::key_server::SessionResult {
				origin,
				params: parity_secretstore_primitives::key_server::DocumentKeyShadowRetrievalParams {
					key_id,
					requester: requester_copy,
				},
				result: session_result.map(|(threshold, common_point, encrypted_document_key)| parity_secretstore_primitives::key_server::DocumentKeyShadowRetrievalArtifacts {
					threshold,
					common_point,
					encrypted_document_key,
					participants_coefficients: std::collections::BTreeMap::new(), // TODO
				})
			}
		}.boxed()
	}
}

impl parity_secretstore_primitives::key_server::MessageSigner for KeyServerImpl {
	type SignMessageSchnorrFuture = std::pin::Pin<Box<dyn std::future::Future<Output = parity_secretstore_primitives::key_server::SchnorrSigningResult> + Send>>;
	type SignMessageEcdsaFuture = std::pin::Pin<Box<dyn std::future::Future<Output = parity_secretstore_primitives::key_server::EcdsaSigningResult> + Send>>;

	fn sign_message_schnorr(
		&self,
		origin: Option<parity_secretstore_primitives::key_server::Origin>,
		key_id: ServerKeyId,
		requester: Requester,
		message: parity_secretstore_primitives::H256,
	) -> Self::SignMessageSchnorrFuture {
		let key_server_core = self.data.clone();
		async move {
			let requester_copy = requester.clone();
			let session_result = async move {
				let session = key_server_core
					.lock()
					.cluster
					.new_schnorr_signing_session(key_id, requester, None, message)?; // TODO: pass origin || assert(None)
				session
					.into_wait_future()
					.compat()
					.await
			}.await;

			parity_secretstore_primitives::key_server::SessionResult {
				origin,
				params: parity_secretstore_primitives::key_server::SchnorrSigningParams {
					key_id,
					requester: requester_copy,
				},
				result: session_result.map(|(signature_c, signature_s)| parity_secretstore_primitives::key_server::SchnorrSigningArtifacts {
					signature_c: *signature_c,
					signature_s: *signature_s,
				})
			}
		}.boxed()
	}

	fn sign_message_ecdsa(
		&self,
		origin: Option<parity_secretstore_primitives::key_server::Origin>,
		key_id: ServerKeyId,
		requester: Requester,
		message: parity_secretstore_primitives::H256,
	) -> Self::SignMessageEcdsaFuture {
		let key_server_core = self.data.clone();
		async move {
			let requester_copy = requester.clone();
			let session_result = async move {
				let session = key_server_core
					.lock()
					.cluster
					.new_ecdsa_signing_session(key_id, requester, None, message)?; // TODO: pass origin || assert(None)
				session
					.into_wait_future()
					.compat()
					.await
			}.await;

			parity_secretstore_primitives::key_server::SessionResult {
				origin,
				params: parity_secretstore_primitives::key_server::EcdsaSigningParams {
					key_id,
					requester: requester_copy,
				},
				result: session_result.map(|signature| parity_secretstore_primitives::key_server::EcdsaSigningArtifacts {
					signature,
				})
			}
		}.boxed()
	}
}

impl parity_secretstore_primitives::key_server::AdminSessionsServer for KeyServerImpl {
	type ChangeServersSetFuture = std::pin::Pin<Box<dyn std::future::Future<Output = parity_secretstore_primitives::key_server::SessionResult<(), ()>> + Send>>;

	fn change_servers_set(
		&self,
		_origin: Option<parity_secretstore_primitives::key_server::Origin>,
		_old_set_signature: parity_secretstore_primitives::Signature,
		_new_set_signature: parity_secretstore_primitives::Signature,
		_new_servers_set: BTreeSet<parity_secretstore_primitives::KeyServerPublic>,
	) -> Self::ChangeServersSetFuture {
		unimplemented!("TODO")
	}
}

#[cfg(test)]
pub mod tests {
	use ethereum_types::H256;
	use parity_crypto::publickey::{Random, Generator, verify_public};
	use parity_secretstore_primitives::key_storage::KeyStorage;
	use crate::types::Requester;
	use crate::traits::{ServerKeyGenerator, DocumentKeyServer, MessageSigner};
	use super::KeyServerImpl;
	use crate::key_server_cluster::{
		math,
		cluster::tests::{MessageLoop, make_clusters},
	};

	fn make_key_server(ml: &MessageLoop, index: usize) -> KeyServerImpl {
		KeyServerImpl::new(
			ml.cluster(index).client(),
			ml.acl_storage(index).clone(),
			ml.key_storage(index).clone(),
		).unwrap()
	}

	#[test]
	fn document_key_generation_and_retrieval_works_over_network_with_single_node() {
		let _ = ::env_logger::try_init();
		let ml = make_clusters(1);
		let key_server0 = make_key_server(&ml, 0);

		// generate document key
		let threshold = 0;
		let document = Random.generate().unwrap().secret().clone();
		let secret = Random.generate().unwrap().secret().clone();
		let signature: Requester = parity_crypto::publickey::sign(&secret, &document).unwrap().into();
		let generated_key = ml.loop_until_future_completed(
			key_server0.generate_document_key(
				None,
				*document,
				signature.clone(),
				threshold,
			)
		).result.unwrap().document_key;

		// now let's try to retrieve key back
		let retrieved_key = ml.loop_until_future_completed(
			key_server0.restore_document_key(
				None,
				*document,
				signature.clone(),
			)
		).result.unwrap().document_key;
		assert_eq!(retrieved_key, generated_key);
	}

	#[test]
	fn document_key_generation_and_retrieval_works_over_network_with_3_nodes() {
		let _ = ::env_logger::try_init();
		let ml = make_clusters(3);

		let test_cases = [0, 1, 2];
		for threshold in &test_cases {
			// generate document key
			let document = Random.generate().unwrap().secret().clone();
			let secret = Random.generate().unwrap().secret().clone();
			let signature: Requester = parity_crypto::publickey::sign(&secret, &document).unwrap().into();
			let generated_key = ml.loop_until_future_completed(
				make_key_server(&ml, 0).generate_document_key(
					None,
					*document,
					signature.clone(),
					*threshold,
				)
			).result.unwrap().document_key;

			// now let's try to retrieve key back
			for i in 0..3 {
				let retrieved_key = ml.loop_until_future_completed(
					make_key_server(&ml, i).restore_document_key(
						None,
						*document,
						signature.clone(),
					)
				).result.unwrap().document_key;
				assert_eq!(retrieved_key, generated_key);

				let key_share = ml.key_storage(i).get(&document).unwrap().unwrap();
				assert!(key_share.common_point.is_some());
				assert!(key_share.encrypted_point.is_some());
			}
		}
	}

	#[test]
	fn server_key_generation_and_storing_document_key_works_over_network_with_3_nodes() {
		let _ = ::env_logger::try_init();
		let ml = make_clusters(3);

		let test_cases = [0, 1, 2];
		for threshold in &test_cases {
			// generate server key
			let server_key_id = Random.generate().unwrap().secret().clone();
			let requestor_secret = Random.generate().unwrap().secret().clone();
			let signature: Requester = parity_crypto::publickey::sign(&requestor_secret, &server_key_id).unwrap().into();
			let server_public = ml.loop_until_future_completed(
				make_key_server(&ml, 0).generate_key(
					None,
					*server_key_id,
					signature.clone(),
					*threshold,
				)
			).result.unwrap().key;

			// generate document key (this is done by KS client so that document key is unknown to any KS)
			let generated_key = Random.generate().unwrap().public().clone();
			let encrypted_document_key = math::encrypt_secret(&generated_key, &server_public).unwrap();

			// store document key
			ml.loop_until_future_completed(
				make_key_server(&ml, 0).store_document_key(
					None,
					*server_key_id,
					signature.clone(),
					encrypted_document_key.common_point,
					encrypted_document_key.encrypted_point,
				)
			).result.unwrap();

			// now let's try to retrieve key back
			for i in 0..3 {
				let retrieved_key = ml.loop_until_future_completed(
					make_key_server(&ml, i).restore_document_key(
						None,
						*server_key_id,
						signature.clone()
					)
				).result.unwrap().document_key;
				assert_eq!(retrieved_key, generated_key);
			}
		}
	}

	#[test]
	fn server_key_generation_and_message_signing_works_over_network_with_3_nodes() {
		let _ = ::env_logger::try_init();
		let ml = make_clusters(3);

		let test_cases = [0, 1, 2];
		for threshold in &test_cases {
			// generate server key
			let server_key_id = Random.generate().unwrap().secret().clone();
			let requestor_secret = Random.generate().unwrap().secret().clone();
			let signature: Requester = parity_crypto::publickey::sign(&requestor_secret, &server_key_id).unwrap().into();
			let server_public = ml.loop_until_future_completed(
				make_key_server(&ml, 0).generate_key(
					None,
					*server_key_id,
					signature.clone(),
					*threshold,
				)
			).result.unwrap().key;

			// sign message
			let message_hash = H256::from_low_u64_be(42);
			let signature = ml.loop_until_future_completed(
				make_key_server(&ml, 0).sign_message_schnorr(
					None,
					*server_key_id,
					signature,
					message_hash,
				)
			).result.unwrap();

			// check signature
			let signature_c = signature.signature_c.as_fixed_bytes().clone().into();
			let signature_s = signature.signature_s.as_fixed_bytes().clone().into();
			assert_eq!(math::verify_schnorr_signature(&server_public, &(signature_c, signature_s), &message_hash), Ok(true));
		}
	}

	#[test]
	fn decryption_session_is_delegated_when_node_does_not_have_key_share() {
		let _ = ::env_logger::try_init();
		let ml = make_clusters(3);

		// generate document key
		let threshold = 0;
		let document = Random.generate().unwrap().secret().clone();
		let secret = Random.generate().unwrap().secret().clone();
		let signature: Requester = parity_crypto::publickey::sign(&secret, &document).unwrap().into();
		let generated_key = ml.loop_until_future_completed(
			make_key_server(&ml, 0).generate_document_key(
				None,
				*document,
				signature.clone(),
				threshold,
			)
		).result.unwrap().document_key;

		// remove key from node0
		ml.key_storage(0).remove(&document).unwrap();

		// now let's try to retrieve key back by requesting it from node0, so that session must be delegated
		let retrieved_key = ml.loop_until_future_completed(
			make_key_server(&ml, 0).restore_document_key(
				None,
				*document,
				signature,
			)
		).result.unwrap().document_key;
		assert_eq!(retrieved_key, generated_key);
	}

	#[test]
	fn schnorr_signing_session_is_delegated_when_node_does_not_have_key_share() {
		let _ = ::env_logger::try_init();
		let ml = make_clusters(3);
		let threshold = 1;

		// generate server key
		let server_key_id = Random.generate().unwrap().secret().clone();
		let requestor_secret = Random.generate().unwrap().secret().clone();
		let signature: Requester = parity_crypto::publickey::sign(&requestor_secret, &server_key_id).unwrap().into();
		let server_public = ml.loop_until_future_completed(
			make_key_server(&ml, 0).generate_key(
				None,
				*server_key_id,
				signature.clone(),
				threshold,
			)
		).result.unwrap().key;

		// remove key from node0
		ml.key_storage(0).remove(&server_key_id).unwrap();

		// sign message
		let message_hash = H256::from_low_u64_be(42);
		let signature = ml.loop_until_future_completed(
			make_key_server(&ml, 0).sign_message_schnorr(
				None,
				*server_key_id,
				signature,
				message_hash,
			)
		).result.unwrap();

		// check signature
		let signature_c = signature.signature_c.as_fixed_bytes().clone().into();
		let signature_s = signature.signature_s.as_fixed_bytes().clone().into();
		assert_eq!(math::verify_schnorr_signature(&server_public, &(signature_c, signature_s), &message_hash), Ok(true));
	}

	#[test]
	fn ecdsa_signing_session_is_delegated_when_node_does_not_have_key_share() {
		let _ = ::env_logger::try_init();
		let ml = make_clusters(4);
		let threshold = 1;

		// generate server key
		let server_key_id = Random.generate().unwrap().secret().clone();
		let requestor_secret = Random.generate().unwrap().secret().clone();
		let signature = parity_crypto::publickey::sign(&requestor_secret, &server_key_id).unwrap();
		let server_public = ml.loop_until_future_completed(
			make_key_server(&ml, 0).generate_key(
				None,
				*server_key_id,
				signature.clone().into(),
				threshold,
			)
		).result.unwrap().key;

		// remove key from node0
		ml.key_storage(0).remove(&server_key_id).unwrap();

		// sign message
		let message_hash = H256::random();
		let signature = ml.loop_until_future_completed(
			make_key_server(&ml, 0).sign_message_ecdsa(
				None,
				*server_key_id,
				signature.clone().into(),
				message_hash,
			)
		).result.unwrap().signature;

		// check signature
		assert!(verify_public(&server_public, &signature.into(), &message_hash).unwrap());
	}
}
