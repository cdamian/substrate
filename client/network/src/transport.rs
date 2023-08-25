// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Transport that serves as a common ground for all connections.

use either::Either;
use libp2p::{core::{
	muxing::StreamMuxerBox,
	transport::{Boxed, OptionalTransport},
	upgrade,
}, dns, identity, noise, tcp, websocket, PeerId, Transport, TransportExt, InboundUpgrade, OutboundUpgrade};
use std::{sync::Arc, time::Duration};
use std::future::Future;
use std::pin::Pin;
use asynchronous_codec::{Decoder, Encoder, Framed, FramedParts};
use bytes::BytesMut;
use futures::{AsyncRead, AsyncWrite, FutureExt, SinkExt};
use futures::StreamExt;

pub use libp2p::bandwidth::BandwidthSinks;
use libp2p::core::UpgradeInfo;
use libp2p::identity::{Keypair, PublicKey};
use unsigned_varint::codec::UviBytes;

/// Builds the transport that serves as a common ground for all connections.
///
/// If `memory_only` is true, then only communication within the same process are allowed. Only
/// addresses with the format `/memory/...` are allowed.
///
/// `yamux_window_size` is the maximum size of the Yamux receive windows. `None` to leave the
/// default (256kiB).
///
/// `yamux_maximum_buffer_size` is the maximum allowed size of the Yamux buffer. This should be
/// set either to the maximum of all the maximum allowed sizes of messages frames of all
/// high-level protocols combined, or to some generously high value if you are sure that a maximum
/// size is enforced on all high-level protocols.
///
/// Returns a `BandwidthSinks` object that allows querying the average bandwidth produced by all
/// the connections spawned with this transport.
pub fn build_transport(
	keypair: identity::Keypair,
	memory_only: bool,
	yamux_window_size: Option<u32>,
	yamux_maximum_buffer_size: usize,
) -> (Boxed<(PeerId, StreamMuxerBox)>, Arc<BandwidthSinks>) {
	// Build the base layer of the transport.
	let transport = if !memory_only {
		// Main transport: DNS(TCP)
		let tcp_config = tcp::Config::new().nodelay(true);
		let tcp_trans = tcp::tokio::Transport::new(tcp_config.clone());
		let dns_init = dns::TokioDnsConfig::system(tcp_trans);

		Either::Left(if let Ok(dns) = dns_init {
			// WS + WSS transport
			//
			// Main transport can't be used for `/wss` addresses because WSS transport needs
			// unresolved addresses (BUT WSS transport itself needs an instance of DNS transport to
			// resolve and dial addresses).
			let tcp_trans = tcp::tokio::Transport::new(tcp_config);
			let dns_for_wss = dns::TokioDnsConfig::system(tcp_trans)
				.expect("same system_conf & resolver to work");
			Either::Left(websocket::WsConfig::new(dns_for_wss).or_transport(dns))
		} else {
			// In case DNS can't be constructed, fallback to TCP + WS (WSS won't work)
			let tcp_trans = tcp::tokio::Transport::new(tcp_config.clone());
			let desktop_trans = websocket::WsConfig::new(tcp_trans)
				.or_transport(tcp::tokio::Transport::new(tcp_config));
			Either::Right(desktop_trans)
		})
	} else {
		Either::Right(OptionalTransport::some(libp2p::core::transport::MemoryTransport::default()))
	};

	let authentication_config = TestHandshake::new(keypair);
	let multiplexing_config = {
		let mut yamux_config = libp2p::yamux::Config::default();
		// Enable proper flow-control: window updates are only sent when
		// buffered data has been consumed.
		yamux_config.set_window_update_mode(libp2p::yamux::WindowUpdateMode::on_read());
		yamux_config.set_max_buffer_size(yamux_maximum_buffer_size);

		if let Some(yamux_window_size) = yamux_window_size {
			yamux_config.set_receive_window_size(yamux_window_size);
		}

		yamux_config
	};

	let transport = transport
		.upgrade(upgrade::Version::V1Lazy)
		.authenticate(authentication_config)
		.multiplex(multiplexing_config)
		.timeout(Duration::from_secs(20))
		.boxed();

	transport.with_bandwidth_logging()
}

#[derive(Clone)]
struct TestHandshake {
	identity: Keypair,
}

impl TestHandshake {
	fn new(identity: Keypair) -> Self {
		TestHandshake { identity }
	}

	async fn send_handshake_info<T, U>(&self, framed_socket: &mut Framed<T, U>) -> Result<(), TestHandshakeError>
		where
			T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
			U: Encoder<Item=BytesMut>,
	{
		// Send public key.
		let encoded_key = self.identity.public().encode_protobuf();

		framed_socket.send(BytesMut::from(encoded_key.as_slice()))
			.await
			.map_err(|_| TestHandshakeError::SendError)?;

		// Send signature.
		let local_peer_id = PeerId::from(self.identity.public());

		let sig = self.identity.sign(local_peer_id.to_bytes().as_slice())
			.map_err(|_| TestHandshakeError::SigningError)?;

		framed_socket.send(BytesMut::from(sig.as_slice()))
			.await
			.map_err(|_| TestHandshakeError::SendError)?;

		Ok(())
	}

	async fn receive_handshake_info<T, U>(&self, framed_socket: &mut Framed<T, U>) -> Result<(PublicKey, PeerId, BytesMut), TestHandshakeError>
		where
			T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
			U: Decoder<Item=BytesMut>,
	{
		// Receive public key.
		let rec = framed_socket.next()
			.await
			.ok_or(TestHandshakeError::AwaitError)?
			.map_err(|_| TestHandshakeError::ReceiveError)?;

		let remote_public_key = PublicKey::try_decode_protobuf(&rec)
			.map_err(|_| TestHandshakeError::KeyDecodeError)?;

		let remote_peer_id = PeerId::from(&remote_public_key);

		// Receive signature.
		let sig = framed_socket.next()
			.await
			.ok_or(TestHandshakeError::AwaitError)?
			.map_err(|_| TestHandshakeError::ReceiveError)?;

		Ok((remote_public_key, remote_peer_id, sig))
	}
}

const PROTOCOL_NAME: &str = "/test-handshake";

impl UpgradeInfo for TestHandshake {
	type Info = &'static str;
	type InfoIter = std::iter::Once<Self::Info>;

	fn protocol_info(&self) -> Self::InfoIter {
		std::iter::once(PROTOCOL_NAME)
	}
}

impl<T> InboundUpgrade<T> for TestHandshake
	where
		T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
	type Output = (PeerId, T);
	type Error = TestHandshakeError;
	type Future = Pin<Box<dyn Future<Output=Result<Self::Output, Self::Error>> + Send>>;

	fn upgrade_inbound(self, socket: T, _: Self::Info) -> Self::Future {
		async move {
			let mut framed_socket = Framed::new(socket, UviBytes::default());

			self.send_handshake_info(&mut framed_socket).await?;

			let (remote_public_key, remote_peer_id, sig) = self.receive_handshake_info(&mut framed_socket).await?;

			if !remote_public_key.verify(remote_peer_id.to_bytes().as_slice(), &sig) {
				return Err(TestHandshakeError::SignatureError);
			}

			let FramedParts { io, .. } = framed_socket.into_parts();

			Ok((remote_peer_id, io))
		}.boxed()
	}
}

impl<T> OutboundUpgrade<T> for TestHandshake
	where
		T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
	type Output = (PeerId, T);
	type Error = TestHandshakeError;
	type Future = Pin<Box<dyn Future<Output=Result<Self::Output, Self::Error>> + Send>>;

	fn upgrade_outbound(self, socket: T, _: Self::Info) -> Self::Future {
		async move {
			let mut framed_socket = Framed::new(socket, UviBytes::default());

			let (remote_public_key, remote_peer_id, sig) = self.receive_handshake_info(&mut framed_socket).await?;

			if !remote_public_key.verify(remote_peer_id.to_bytes().as_slice(), &sig) {
				return Err(TestHandshakeError::SignatureError);
			}

			self.send_handshake_info(&mut framed_socket).await?;

			let FramedParts { io, .. } = framed_socket.into_parts();

			Ok((remote_peer_id, io))
		}.boxed()
	}
}

#[derive(Debug, thiserror::Error)]
enum TestHandshakeError {
	#[error("Send error")]
	SendError,
	#[error("Receive error")]
	ReceiveError,
	#[error("Await error")]
	AwaitError,
	#[error("Signing error")]
	SigningError,
	#[error("Signature error")]
	SignatureError,
	#[error("Key decode error")]
	KeyDecodeError,
}