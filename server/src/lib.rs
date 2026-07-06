//! Server-side library for the secure private messaging backend.
//!
//! The server stores public authentication material and relays encrypted
//! envelopes only. It must never generate client private keys or decrypt message
//! payloads.

pub mod admin;
pub mod auth;
pub mod crypto;
pub mod groups;
pub mod messaging;
