#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatchetHeader {
    pub sender_ratchet_public_key_x25519: [u8; 32],
    pub previous_chain_length: u32,
    pub message_number: u32,
}

impl RatchetHeader {
    pub fn new(
        sender_ratchet_public_key_x25519: [u8; 32],
        previous_chain_length: u32,
        message_number: u32,
    ) -> Self {
        Self {
            sender_ratchet_public_key_x25519,
            previous_chain_length,
            message_number,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatchetSessionMetadata {
    pub session_id: String,
    pub local_device_id: String,
    pub remote_device_id: String,
    pub root_key_version: u32,
}

impl RatchetSessionMetadata {
    pub fn new(
        session_id: impl Into<String>,
        local_device_id: impl Into<String>,
        remote_device_id: impl Into<String>,
        root_key_version: u32,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            local_device_id: local_device_id.into(),
            remote_device_id: remote_device_id.into(),
            root_key_version,
        }
    }
}
