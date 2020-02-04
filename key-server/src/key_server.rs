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
use futures::{future::{err, result}, Future};
use parking_lot::Mutex;
use parity_crypto::DEFAULT_MAC;
use parity_crypto::publickey::public_to_address;
use parity_runtime::Executor;
use parity_secretstore_primitives::acl_storage::AclStorage;
use parity_secretstore_primitives::key_server_set::KeyServerSet;
use parity_secretstore_primitives::key_storage::KeyStorage;
use crate::blockchain::SigningKeyPair;
use crate::key_server_cluster::{math, new_network_cluster, ClusterSession, WaitableSession};
use crate::traits::{AdminSessionsServer, ServerKeyGenerator, DocumentKeyServer, MessageSigner, KeyServer};
use crate::types::{Error, Public, RequestSignature, Requester, ServerKeyId, EncryptedDocumentKey, EncryptedDocumentKeyShadow,
	ClusterConfiguration, MessageHash, EncryptedMessageSignature, NodeId};
use crate::key_server_cluster::{ClusterClient, ClusterConfiguration as NetClusterConfiguration, NetConnectionsManagerConfig};

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
	pub fn new(config: &ClusterConfiguration, key_server_set: Arc<dyn KeyServerSet>, self_key_pair: Arc<dyn SigningKeyPair>,
		acl_storage: Arc<dyn AclStorage>, key_storage: Arc<dyn KeyStorage>, executor: Executor) -> Result<Self, Error>
	{
		Ok(KeyServerImpl {
			data: Arc::new(Mutex::new(KeyServerCore::new(config, key_server_set, self_key_pair, acl_storage, key_storage, executor)?)),
		})
	}

	/// Get cluster client reference.
	pub fn cluster(&self) -> Arc<dyn ClusterClient> {
		self.data.lock().cluster.clone()
	}
}

impl KeyServer for KeyServerImpl {}

impl AdminSessionsServer for KeyServerImpl {
	fn change_servers_set(
		&self,
		old_set_signature: RequestSignature,
		new_set_signature: RequestSignature,
		new_servers_set: BTreeSet<NodeId>,
	) -> Box<dyn Future<Item=(), Error=Error> + Send> {
		return_session(self.data.lock().cluster
			.new_servers_set_change_session(None, None, new_servers_set, old_set_signature, new_set_signature))
	}
}

impl ServerKeyGenerator for KeyServerImpl {
	fn generate_key(
		&self,
		key_id: ServerKeyId,
		author: Requester,
		threshold: usize,
	) -> Box<dyn Future<Item=Public, Error=Error> + Send> {
		// recover requestor' address key from signature
		let address = author.address(&key_id);

		// generate server key
		return_session(address.and_then(|address| self.data.lock().cluster
			.new_generation_session(key_id, None, address, threshold)))
	}

	fn restore_key_public(
		&self,
		key_id: ServerKeyId,
		author: Requester,
	) -> Box<dyn Future<Item=Public, Error=Error> + Send> {
		// recover requestor' public key from signature
		let session_and_address = author
			.address(&key_id)
			.and_then(|address| self.data.lock().cluster.new_key_version_negotiation_session(key_id)
				.map(|session| (session, address)));
		let (session, address) = match session_and_address {
			Ok((session, address)) => (session, address),
			Err(error) => return Box::new(err(error)),
		};

		// negotiate key version && retrieve common key data
		let core_session = session.session.clone();
		Box::new(session.into_wait_future()
			.and_then(move |_| core_session.common_key_data()
				.map(|key_share| (key_share, address)))
			.and_then(|(key_share, address)| if key_share.author == address {
				Ok(key_share.public)
			} else {
				Err(Error::AccessDenied)
			}))
	}
}

impl DocumentKeyServer for KeyServerImpl {
	fn store_document_key(
		&self,
		key_id: ServerKeyId,
		author: Requester,
		common_point: Public,
		encrypted_document_key: Public,
	) -> Box<dyn Future<Item=(), Error=Error> + Send> {
		// store encrypted key
		return_session(self.data.lock().cluster.new_encryption_session(key_id,
			author.clone(), common_point, encrypted_document_key))
	}

	fn generate_document_key(
		&self,
		key_id: ServerKeyId,
		author: Requester,
		threshold: usize,
	) -> Box<dyn Future<Item=EncryptedDocumentKey, Error=Error> + Send> {
		// recover requestor' public key from signature
		let public = result(author.public(&key_id));

		// generate server key
		let data = self.data.clone();
		let server_key = public.and_then(move |public| {
			let data = data.lock();
			let session = data.cluster.new_generation_session(key_id, None, public_to_address(&public), threshold);
			result(session.map(|session| (public, session)))
		})
		.and_then(|(public, session)| session.into_wait_future().map(move |server_key| (public, server_key)));

		// generate random document key
		let document_key = server_key.and_then(|(public, server_key)|
			result(math::generate_random_point()
				.and_then(|document_key| math::encrypt_secret(&document_key, &server_key)
					.map(|encrypted_document_key| (public, document_key, encrypted_document_key))))
		);

		// store document key in the storage
		let data = self.data.clone();
		let stored_document_key = document_key.and_then(move |(public, document_key, encrypted_document_key)| {
			let data = data.lock();
			let session = data.cluster.new_encryption_session(key_id,
				author.clone(), encrypted_document_key.common_point, encrypted_document_key.encrypted_point);
			result(session.map(|session| (public, document_key, session)))
		})
		.and_then(|(public, document_key, session)| session.into_wait_future().map(move |_| (public, document_key)));

		// encrypt document key with requestor public key
		let encrypted_document_key = stored_document_key
			.and_then(|(public, document_key)| parity_crypto::publickey::ecies::encrypt(&public, &DEFAULT_MAC, document_key.as_bytes())
				.map_err(|err| Error::Internal(format!("Error encrypting document key: {}", err))));

		Box::new(encrypted_document_key)
	}

	fn restore_document_key(
		&self,
		key_id: ServerKeyId,
		requester: Requester,
	) -> Box<dyn Future<Item=EncryptedDocumentKey, Error=Error> + Send> {
		// recover requestor' public key from signature
		let public = result(requester.public(&key_id));

		// decrypt document key
		let data = self.data.clone();
		let stored_document_key = public.and_then(move |public| {
			let data = data.lock();
			let session = data.cluster.new_decryption_session(key_id, None, requester.clone(), None, false, false);
			result(session.map(|session| (public, session)))
		})
		.and_then(|(public, session)| session.into_wait_future().map(move |document_key| (public, document_key)));

		// encrypt document key with requestor public key
		let encrypted_document_key = stored_document_key
			.and_then(|(public, document_key)|
				parity_crypto::publickey::ecies::encrypt(&public, &DEFAULT_MAC, document_key.decrypted_secret.as_bytes())
					.map_err(|err| Error::Internal(format!("Error encrypting document key: {}", err))));

		Box::new(encrypted_document_key)
	}

	fn restore_document_key_shadow(
		&self,
		key_id: ServerKeyId,
		requester: Requester,
	) -> Box<dyn Future<Item=EncryptedDocumentKeyShadow, Error=Error> + Send> {
		return_session(self.data.lock().cluster.new_decryption_session(key_id,
			None, requester.clone(), None, true, false))
	}
}

impl MessageSigner for KeyServerImpl {
	fn sign_message_schnorr(
		&self,
		key_id: ServerKeyId,
		requester: Requester,
		message: MessageHash,
	) -> Box<dyn Future<Item=EncryptedMessageSignature, Error=Error> + Send> {
		// recover requestor' public key from signature
		let public = result(requester.public(&key_id));

		// sign message
		let data = self.data.clone();
		let signature = public.and_then(move |public| {
			let data = data.lock();
			let session = data.cluster.new_schnorr_signing_session(key_id, requester.clone().into(), None, message);
			result(session.map(|session| (public, session)))
		})
		.and_then(|(public, session)| session.into_wait_future().map(move |signature| (public, signature)));

		// compose two message signature components into single one
		let combined_signature = signature.map(|(public, signature)| {
			let mut combined_signature = [0; 64];
			combined_signature[..32].clone_from_slice(signature.0.as_bytes());
			combined_signature[32..].clone_from_slice(signature.1.as_bytes());
			(public, combined_signature)
		});

		// encrypt signature with requestor public key
		let encrypted_signature = combined_signature
			.and_then(|(public, combined_signature)| parity_crypto::publickey::ecies::encrypt(&public, &DEFAULT_MAC, &combined_signature)
				.map_err(|err| Error::Internal(format!("Error encrypting message signature: {}", err))));

		Box::new(encrypted_signature)
	}

	fn sign_message_ecdsa(
		&self,
		key_id: ServerKeyId,
		requester: Requester,
		message: MessageHash,
	) -> Box<dyn Future<Item=EncryptedMessageSignature, Error=Error> + Send> {
		// recover requestor' public key from signature
		let public = result(requester.public(&key_id));

		// sign message
		let data = self.data.clone();
		let signature = public.and_then(move |public| {
			let data = data.lock();
			let session = data.cluster.new_ecdsa_signing_session(key_id, requester.clone().into(), None, message);
			result(session.map(|session| (public, session)))
		})
		.and_then(|(public, session)| session.into_wait_future().map(move |signature| (public, signature)));

		// encrypt combined signature with requestor public key
		let encrypted_signature = signature
			.and_then(|(public, signature)| parity_crypto::publickey::ecies::encrypt(&public, &DEFAULT_MAC, &*signature)
				.map_err(|err| Error::Internal(format!("Error encrypting message signature: {}", err))));

		Box::new(encrypted_signature)
	}
}

impl KeyServerCore {
	pub fn new(config: &ClusterConfiguration, key_server_set: Arc<dyn KeyServerSet>, self_key_pair: Arc<dyn SigningKeyPair>,
		acl_storage: Arc<dyn AclStorage>, key_storage: Arc<dyn KeyStorage>, executor: Executor) -> Result<Self, Error>
	{
		let cconfig = NetClusterConfiguration {
			self_key_pair: self_key_pair.clone(),
			key_server_set: key_server_set,
			acl_storage: acl_storage.clone(),
			key_storage: key_storage.clone(),
			admin_public: config.admin_public,
			preserve_sessions: false,
		};
		let net_config = NetConnectionsManagerConfig {
			listen_address: (config.listener_address.address.clone(), config.listener_address.port),
			allow_connecting_to_higher_nodes: config.allow_connecting_to_higher_nodes,
			auto_migrate_enabled: config.auto_migrate_enabled,
		};

		let core = new_network_cluster(executor, cconfig, net_config)?;
		let cluster = core.client();
		core.run()?;

		Ok(KeyServerCore {
			cluster,
			acl_storage,
			key_storage,
		})
	}
}

fn return_session<S: ClusterSession>(
	session: Result<WaitableSession<S>, Error>,
) -> Box<dyn Future<Item=S::SuccessfulResult, Error=Error> + Send> {
	match session {
		Ok(session) => Box::new(session.into_wait_future()),
		Err(error) => Box::new(err(error))
	}
}

// ### EXTRACT: BEGIN ###
use futures03::{
	compat::Future01CompatExt,
	future::{ready, FutureExt},
};

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

// ### EXTRACT: END ###

#[cfg(test)]
pub mod tests {
	use std::collections::BTreeSet;
	use std::time;
	use std::sync::Arc;
	use std::net::SocketAddr;
	use std::collections::BTreeMap;
	use futures::Future;
	use parity_crypto::DEFAULT_MAC;
	use parity_crypto::publickey::{Secret, Random, Generator, verify_public};
	use parity_secretstore_primitives::acl_storage::InMemoryPermissiveAclStorage;
	use parity_secretstore_primitives::key_server_set::InMemoryKeyServerSet;
	use parity_secretstore_primitives::key_storage::{InMemoryKeyStorage, KeyStorage};
	use crate::node_key_pair::PlainNodeKeyPair;
	use crate::key_server_cluster::math;
	use ethereum_types::{H256, H520};
	use parity_runtime::Runtime;
	use crate::types::{Error, Public, ClusterConfiguration, NodeAddress, RequestSignature, ServerKeyId,
		EncryptedDocumentKey, EncryptedDocumentKeyShadow, MessageHash, EncryptedMessageSignature,
		Requester, NodeId};
	use crate::traits::{AdminSessionsServer, ServerKeyGenerator, DocumentKeyServer, MessageSigner, KeyServer};
	use super::KeyServerImpl;

	#[derive(Default)]
	pub struct DummyKeyServer;

	impl KeyServer for DummyKeyServer {}

	impl AdminSessionsServer for DummyKeyServer {
		fn change_servers_set(
			&self,
			_old_set_signature: RequestSignature,
			_new_set_signature: RequestSignature,
			_new_servers_set: BTreeSet<NodeId>,
		) -> Box<dyn Future<Item=(), Error=Error> + Send> {
			unimplemented!("test-only")
		}
	}

	impl ServerKeyGenerator for DummyKeyServer {
		fn generate_key(
			&self,
			_key_id: ServerKeyId,
			_author: Requester,
			_threshold: usize,
		) -> Box<dyn Future<Item=Public, Error=Error> + Send> {
			unimplemented!("test-only")
		}

		fn restore_key_public(
			&self,
			_key_id: ServerKeyId,
			_author: Requester,
		) -> Box<dyn Future<Item=Public, Error=Error> + Send> {
			unimplemented!("test-only")
		}
	}

	impl DocumentKeyServer for DummyKeyServer {
		fn store_document_key(
			&self,
			_key_id: ServerKeyId,
			_author: Requester,
			_common_point: Public,
			_encrypted_document_key: Public,
		) -> Box<dyn Future<Item=(), Error=Error> + Send> {
			unimplemented!("test-only")
		}

		fn generate_document_key(
			&self,
			_key_id: ServerKeyId,
			_author: Requester,
			_threshold: usize,
		) -> Box<dyn Future<Item=EncryptedDocumentKey, Error=Error> + Send> {
			unimplemented!("test-only")
		}

		fn restore_document_key(
			&self,
			_key_id: ServerKeyId,
			_requester: Requester,
		) -> Box<dyn Future<Item=EncryptedDocumentKey, Error=Error> + Send> {
			unimplemented!("test-only")
		}

		fn restore_document_key_shadow(
			&self,
			_key_id: ServerKeyId,
			_requester: Requester,
		) -> Box<dyn Future<Item=EncryptedDocumentKeyShadow, Error=Error> + Send> {
			unimplemented!("test-only")
		}
	}

	impl MessageSigner for DummyKeyServer {
		fn sign_message_schnorr(
			&self,
			_key_id: ServerKeyId,
			_requester: Requester,
			_message: MessageHash,
		) -> Box<dyn Future<Item=EncryptedMessageSignature, Error=Error> + Send> {
			unimplemented!("test-only")
		}

		fn sign_message_ecdsa(
			&self,
			_key_id: ServerKeyId,
			_requester: Requester,
			_message: MessageHash,
		) -> Box<dyn Future<Item=EncryptedMessageSignature, Error=Error> + Send> {
			unimplemented!("test-only")
		}
	}

	fn make_key_servers(start_port: u16, num_nodes: usize) -> (Vec<KeyServerImpl>, Vec<Arc<InMemoryKeyStorage>>, Runtime) {
		let key_pairs: Vec<_> = (0..num_nodes).map(|_| Random.generate().unwrap()).collect();
		let configs: Vec<_> = (0..num_nodes).map(|i| ClusterConfiguration {
				listener_address: NodeAddress {
					address: "127.0.0.1".into(),
					port: start_port + (i as u16),
				},
				nodes: key_pairs.iter().enumerate().map(|(j, kp)| (kp.public().clone(),
					NodeAddress {
						address: "127.0.0.1".into(),
						port: start_port + (j as u16),
					})).collect(),
				key_server_set_contract_address: None,
				allow_connecting_to_higher_nodes: false,
				admin_public: None,
				auto_migrate_enabled: false,
			}).collect();
		let key_servers_set: BTreeMap<Public, SocketAddr> = configs[0].nodes.iter()
			.map(|(k, a)| (k.clone(), format!("{}:{}", a.address, a.port).parse().unwrap()))
			.collect();
		let key_storages = (0..num_nodes).map(|_| Arc::new(InMemoryKeyStorage::default())).collect::<Vec<_>>();
		let runtime = Runtime::with_thread_count(4);
		let key_servers: Vec<_> = configs.into_iter().enumerate().map(|(i, cfg)|
			KeyServerImpl::new(&cfg, Arc::new(InMemoryKeyServerSet::new(false, key_servers_set.clone())),
				Arc::new(PlainNodeKeyPair::new(key_pairs[i].clone())),
				Arc::new(InMemoryPermissiveAclStorage::default()),
				key_storages[i].clone(), runtime.executor()).unwrap()
		).collect();

		// wait until connections are established. It is fast => do not bother with events here
		let start = time::Instant::now();
		let mut tried_reconnections = false;
		loop {
			if key_servers.iter().all(|ks| ks.cluster().is_fully_connected()) {
				break;
			}

			let old_tried_reconnections = tried_reconnections;
			let mut fully_connected = true;
			for key_server in &key_servers {
				if !key_server.cluster().is_fully_connected() {
					fully_connected = false;
					if !old_tried_reconnections {
						tried_reconnections = true;
						key_server.cluster().connect();
					}
				}
			}
			if fully_connected {
				break;
			}
			if time::Instant::now() - start > time::Duration::from_millis(3000) {
				panic!("connections are not established in 3000ms");
			}
		}

		(key_servers, key_storages, runtime)
	}

	#[test]
	fn document_key_generation_and_retrievement_works_over_network_with_single_node() {
		let _ = ::env_logger::try_init();
		let (key_servers, _, runtime) = make_key_servers(6070, 1);

		// generate document key
		let threshold = 0;
		let document = Random.generate().unwrap().secret().clone();
		let secret = Random.generate().unwrap().secret().clone();
		let signature: Requester = parity_crypto::publickey::sign(&secret, &document).unwrap().into();
		let generated_key = key_servers[0].generate_document_key(
			*document,
			signature.clone(),
			threshold,
		).wait().unwrap();
		let generated_key = parity_crypto::publickey::ecies::decrypt(&secret, &DEFAULT_MAC, &generated_key).unwrap();

		// now let's try to retrieve key back
		for key_server in key_servers.iter() {
			let retrieved_key = key_server.restore_document_key(
				*document,
				signature.clone(),
			).wait().unwrap();
			let retrieved_key = parity_crypto::publickey::ecies::decrypt(&secret, &DEFAULT_MAC, &retrieved_key).unwrap();
			assert_eq!(retrieved_key, generated_key);
		}
		drop(runtime);
	}

	#[test]
	fn document_key_generation_and_retrievement_works_over_network_with_3_nodes() {
		let _ = ::env_logger::try_init();
		let (key_servers, key_storages, runtime) = make_key_servers(6080, 3);

		let test_cases = [0, 1, 2];
		for threshold in &test_cases {
			// generate document key
			let document = Random.generate().unwrap().secret().clone();
			let secret = Random.generate().unwrap().secret().clone();
			let signature: Requester = parity_crypto::publickey::sign(&secret, &document).unwrap().into();
			let generated_key = key_servers[0].generate_document_key(
				*document,
				signature.clone(),
				*threshold,
			).wait().unwrap();
			let generated_key = parity_crypto::publickey::ecies::decrypt(&secret, &DEFAULT_MAC, &generated_key).unwrap();

			// now let's try to retrieve key back
			for (i, key_server) in key_servers.iter().enumerate() {
				let retrieved_key = key_server.restore_document_key(
					*document,
					signature.clone(),
				).wait().unwrap();
				let retrieved_key = parity_crypto::publickey::ecies::decrypt(&secret, &DEFAULT_MAC, &retrieved_key).unwrap();
				assert_eq!(retrieved_key, generated_key);

				let key_share = key_storages[i].get(&document).unwrap().unwrap();
				assert!(key_share.common_point.is_some());
				assert!(key_share.encrypted_point.is_some());
			}
		}
		drop(runtime);
	}

	#[test]
	fn server_key_generation_and_storing_document_key_works_over_network_with_3_nodes() {
		let _ = ::env_logger::try_init();
		let (key_servers, _, runtime) = make_key_servers(6090, 3);

		let test_cases = [0, 1, 2];
		for threshold in &test_cases {
			// generate server key
			let server_key_id = Random.generate().unwrap().secret().clone();
			let requestor_secret = Random.generate().unwrap().secret().clone();
			let signature: Requester = parity_crypto::publickey::sign(&requestor_secret, &server_key_id).unwrap().into();
			let server_public = key_servers[0].generate_key(
				*server_key_id,
				signature.clone(),
				*threshold,
			).wait().unwrap();

			// generate document key (this is done by KS client so that document key is unknown to any KS)
			let generated_key = Random.generate().unwrap().public().clone();
			let encrypted_document_key = math::encrypt_secret(&generated_key, &server_public).unwrap();

			// store document key
			key_servers[0].store_document_key(*server_key_id, signature.clone(),
				encrypted_document_key.common_point, encrypted_document_key.encrypted_point).wait().unwrap();

			// now let's try to retrieve key back
			for key_server in key_servers.iter() {
				let retrieved_key = key_server.restore_document_key(*server_key_id, signature.clone()).wait().unwrap();
				let retrieved_key = parity_crypto::publickey::ecies::decrypt(&requestor_secret, &DEFAULT_MAC, &retrieved_key).unwrap();
				let retrieved_key = Public::from_slice(&retrieved_key);
				assert_eq!(retrieved_key, generated_key);
			}
		}
		drop(runtime);
	}

	#[test]
	fn server_key_generation_and_message_signing_works_over_network_with_3_nodes() {
		let _ = ::env_logger::try_init();
		let (key_servers, _, runtime) = make_key_servers(6100, 3);

		let test_cases = [0, 1, 2];
		for threshold in &test_cases {
			// generate server key
			let server_key_id = Random.generate().unwrap().secret().clone();
			let requestor_secret = Random.generate().unwrap().secret().clone();
			let signature: Requester = parity_crypto::publickey::sign(&requestor_secret, &server_key_id).unwrap().into();
			let server_public = key_servers[0].generate_key(
				*server_key_id,
				signature.clone(),
				*threshold,
			).wait().unwrap();

			// sign message
			let message_hash = H256::from_low_u64_be(42);
			let combined_signature = key_servers[0].sign_message_schnorr(
				*server_key_id,
				signature,
				message_hash,
			).wait().unwrap();
			let combined_signature = parity_crypto::publickey::ecies::decrypt(&requestor_secret, &DEFAULT_MAC, &combined_signature).unwrap();
			let signature_c = Secret::copy_from_slice(&combined_signature[..32]).unwrap();
			let signature_s = Secret::copy_from_slice(&combined_signature[32..]).unwrap();

			// check signature
			assert_eq!(math::verify_schnorr_signature(&server_public, &(signature_c, signature_s), &message_hash), Ok(true));
		}
		drop(runtime);
	}

	#[test]
	fn decryption_session_is_delegated_when_node_does_not_have_key_share() {
		let _ = ::env_logger::try_init();
		let (key_servers, key_storages, runtime) = make_key_servers(6110, 3);

		// generate document key
		let threshold = 0;
		let document = Random.generate().unwrap().secret().clone();
		let secret = Random.generate().unwrap().secret().clone();
		let signature: Requester = parity_crypto::publickey::sign(&secret, &document).unwrap().into();
		let generated_key = key_servers[0].generate_document_key(
			*document,
			signature.clone(),
			threshold,
		).wait().unwrap();
		let generated_key = parity_crypto::publickey::ecies::decrypt(&secret, &DEFAULT_MAC, &generated_key).unwrap();

		// remove key from node0
		key_storages[0].remove(&document).unwrap();

		// now let's try to retrieve key back by requesting it from node0, so that session must be delegated
		let retrieved_key = key_servers[0].restore_document_key(*document, signature).wait().unwrap();
		let retrieved_key = parity_crypto::publickey::ecies::decrypt(&secret, &DEFAULT_MAC, &retrieved_key).unwrap();
		assert_eq!(retrieved_key, generated_key);
		drop(runtime);
	}

	#[test]
	fn schnorr_signing_session_is_delegated_when_node_does_not_have_key_share() {
		let _ = ::env_logger::try_init();
		let (key_servers, key_storages, runtime) = make_key_servers(6114, 3);
		let threshold = 1;

		// generate server key
		let server_key_id = Random.generate().unwrap().secret().clone();
		let requestor_secret = Random.generate().unwrap().secret().clone();
		let signature: Requester = parity_crypto::publickey::sign(&requestor_secret, &server_key_id).unwrap().into();
		let server_public = key_servers[0].generate_key(*server_key_id, signature.clone(), threshold).wait().unwrap();

		// remove key from node0
		key_storages[0].remove(&server_key_id).unwrap();

		// sign message
		let message_hash = H256::from_low_u64_be(42);
		let combined_signature = key_servers[0].sign_message_schnorr(
			*server_key_id,
			signature,
			message_hash,
		).wait().unwrap();
		let combined_signature = parity_crypto::publickey::ecies::decrypt(&requestor_secret, &DEFAULT_MAC, &combined_signature).unwrap();
		let signature_c = Secret::copy_from_slice(&combined_signature[..32]).unwrap();
		let signature_s = Secret::copy_from_slice(&combined_signature[32..]).unwrap();

		// check signature
		assert_eq!(math::verify_schnorr_signature(&server_public, &(signature_c, signature_s), &message_hash), Ok(true));
		drop(runtime);
	}

	#[test]
	fn ecdsa_signing_session_is_delegated_when_node_does_not_have_key_share() {
		let _ = ::env_logger::try_init();
		let (key_servers, key_storages, runtime) = make_key_servers(6117, 4);
		let threshold = 1;

		// generate server key
		let server_key_id = Random.generate().unwrap().secret().clone();
		let requestor_secret = Random.generate().unwrap().secret().clone();
		let signature = parity_crypto::publickey::sign(&requestor_secret, &server_key_id).unwrap();
		let server_public = key_servers[0].generate_key(
			*server_key_id,
			signature.clone().into(),
			threshold,
		).wait().unwrap();

		// remove key from node0
		key_storages[0].remove(&server_key_id).unwrap();

		// sign message
		let message_hash = H256::random();
		let signature = key_servers[0].sign_message_ecdsa(
			*server_key_id,
			signature.clone().into(),
			message_hash,
		).wait().unwrap();
		let signature = parity_crypto::publickey::ecies::decrypt(&requestor_secret, &DEFAULT_MAC, &signature).unwrap();
		let signature = H520::from_slice(&signature[0..65]);

		// check signature
		assert!(verify_public(&server_public, &signature.into(), &message_hash).unwrap());
		drop(runtime);
	}

	#[test]
	fn servers_set_change_session_works_over_network() {
		// TODO [Test]
	}
}
