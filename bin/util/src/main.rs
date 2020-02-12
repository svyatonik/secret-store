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

use parity_crypto::publickey::{Secret, Signature, Message, sign};

fn main() {
	run().unwrap();
}

fn run() -> Result<(), String> {
	let yaml = clap::load_yaml!("cli.yml");
	let matches = clap::App::from_yaml(yaml).get_matches();
	match matches.subcommand() {
		("sign-server-key-id", Some(sign_key_id_matches)) => sign_key_id(sign_key_id_matches),
		_ => Err("Invalid subcommand".into()),
	}
}

fn sign_key_id(matches: &clap::ArgMatches) -> Result<(), String> {
	let signer_key_str = matches.value_of("signer-secret")
		.expect("signer-secret is required in cli.yml; qed");
	let server_key_id_str = matches.value_of("server-key-id")
		.expect("server-key-id is required in cli.yml; qed");

	let signer_key: Secret = signer_key_str.parse().map_err(|err| format!("{}", err))?;
	let server_key_id: Message = server_key_id_str.parse().map_err(|err| format!("{}", err))?;
	let signed_server_key = sign(&signer_key, &server_key_id).map_err(|err| format!("{}", err))?;

	println!("Signed server key ID: {}", signed_server_key);

	Ok(())
}
