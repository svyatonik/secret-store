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

mod key_server_cluster;
mod types;

mod traits;
mod key_server;
mod serialization;
mod node_key_pair;
mod blockchain;
mod migration;

use std::sync::Arc;
use parity_runtime::Executor;

pub use crate::types::{ServerKeyId, EncryptedDocumentKey, RequestSignature, Public,
	Error, NodeAddress, ServiceConfiguration, ClusterConfiguration};
pub use crate::traits::KeyServer;
pub use crate::blockchain::{SecretStoreChain, SigningKeyPair, ContractAddress, BlockId, BlockNumber, NewBlocksNotify, Filter};
pub use self::node_key_pair::PlainNodeKeyPair;
use parity_secretstore_primitives::{
	acl_storage::AclStorage,
	key_server_set::KeyServerSet,
	key_storage::KeyStorage,
};

/// Start new key server instance
pub fn start(
	self_key_pair: Arc<dyn SigningKeyPair>,
	config: ServiceConfiguration,
	executor: Executor,
	acl_storage: Arc<dyn AclStorage>,
	key_server_set: Arc<dyn KeyServerSet>,
	key_storage: Arc<dyn KeyStorage>,
) -> Result<Arc<key_server::KeyServerImpl>, Error> {
	let key_server = Arc::new(key_server::KeyServerImpl::new(&config.cluster_config, key_server_set.clone(), self_key_pair.clone(),
		acl_storage.clone(), key_storage.clone(), executor.clone())?);

	Ok(key_server)
}
