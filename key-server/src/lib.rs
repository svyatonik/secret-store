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
mod key_storage;
mod serialization;
mod node_key_pair;
mod blockchain;
mod migration;

use std::sync::Arc;
use kvdb::KeyValueDB;
use kvdb_rocksdb::{Database, DatabaseConfig};
use parity_runtime::Executor;

pub use crate::types::{ServerKeyId, EncryptedDocumentKey, RequestSignature, Public,
	Error, NodeAddress, ServiceConfiguration, ClusterConfiguration};
pub use crate::traits::KeyServer;
pub use crate::blockchain::{SecretStoreChain, SigningKeyPair, ContractAddress, BlockId, BlockNumber, NewBlocksNotify, Filter};
pub use self::node_key_pair::PlainNodeKeyPair;
use parity_secretstore_primitives::{
	acl_storage::AclStorage,
	key_server_set::KeyServerSet,
};

/// Open a secret store DB using the given secret store data path. The DB path is one level beneath the data path.
pub fn open_secretstore_db(data_path: &str) -> Result<Arc<dyn KeyValueDB>, String> {
	use std::path::PathBuf;

	migration::upgrade_db(data_path).map_err(|e| e.to_string())?;

	let mut db_path = PathBuf::from(data_path);
	db_path.push("db");
	let db_path = db_path.to_str().ok_or_else(|| "Invalid secretstore path".to_string())?;

	let config = DatabaseConfig::with_columns(1);
	Ok(Arc::new(Database::open(&config, &db_path).map_err(|e| format!("Error opening database: {:?}", e))?))
}

/// Start new key server instance
pub fn start(
	self_key_pair: Arc<dyn SigningKeyPair>,
	config: ServiceConfiguration,
	db: Arc<dyn KeyValueDB>,
	executor: Executor,
	acl_storage: Arc<dyn AclStorage>,
	key_server_set: Arc<dyn KeyServerSet>,
) -> Result<Arc<dyn KeyServer>, Error> {
	let key_storage = Arc::new(key_storage::PersistentKeyStorage::new(db)?);
	let key_server = Arc::new(key_server::KeyServerImpl::new(&config.cluster_config, key_server_set.clone(), self_key_pair.clone(),
		acl_storage.clone(), key_storage.clone(), executor.clone())?);

	Ok(key_server)
}
