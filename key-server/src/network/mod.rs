use std::{
	collections::BTreeSet,
	sync::Arc,
};
use parity_secretstore_primitives::{error::Error, KeyServerId};
use crate::key_server_cluster::message::Message;

pub mod tcp;

/// Connection to the single node. Provides basic information about connected node and
/// allows sending messages to this node.
pub trait Connection: Send + Sync {
	/// Is this inbound connection? This only matters when both nodes are simultaneously establishing
	/// two connections to each other. The agreement is that the inbound connection from the node with
	/// lower KeyServerId is used and the other connection is closed.
	fn is_inbound(&self) -> bool;
	/// Returns id of the connected node.
	fn node_id(&self) -> &KeyServerId;
	/// Returns 'address' of the node to use in traces.
	fn node_address(&self) -> String;
	/// Send message to the connected node.
	fn send_message(&self, message: Message);
}

/// Connections manager. Responsible for keeping us connected to all required nodes.
pub trait ConnectionManager: 'static + Send + Sync {
	/// Returns shared reference to connections provider.
	fn provider(&self) -> Arc<dyn ConnectionProvider>;
	/// Try to reach all disconnected nodes immediately. This method is exposed mostly for
	/// tests, where all 'nodes' are starting listening for incoming connections first and
	/// only after this, they're actually start connecting to each other.
	fn connect(&self);
}

/// Connections provider. Holds all active connections and the set of nodes that we need to
/// connect to. At any moment connection could be lost and the set of connected/disconnected
/// nodes could change (at behalf of the connection manager).
/// Clone operation should be cheap (Arc).
pub trait ConnectionProvider: Send + Sync {
	/// Returns the set of currently connected nodes. Error is returned when our node is
	/// not a part of the cluster ('isolated' node).
	fn connected_nodes(&self) -> Result<BTreeSet<KeyServerId>, Error>;
	/// Returns the set of currently disconnected nodes.
	fn disconnected_nodes(&self) -> BTreeSet<KeyServerId>;
	/// Returns the reference to the active node connection or None if the node is not connected.
	fn connection(&self, node: &KeyServerId) -> Option<Arc<dyn Connection>>;
}
