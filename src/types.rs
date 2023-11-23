use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalIdentitie {
    //  pub id: u64,
    pub next_prekey_id: Option<u64>,
    pub registration_id: Option<u32>,
    pub address: String,
    pub device: String,
    pub private_key: Option<String>,
    pub public_key: String,
    // pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalRatchetKey {
    // pub id: u64,
    pub alice_ratchet_key_public: String,
    pub room_id: u32,
    pub address: String,
    pub device: String,
    pub bob_ratchet_key_private: String,
    pub ratche_key_hash: Option<String>,
    // pub created_at: u64,
}


#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone)]
pub struct SignalSession {
    // pub id: u64,
    pub alice_sender_ratchet_key: Option<String>,
    pub address: String,
    pub device: u32,
    pub bob_sender_ratchet_key: Option<String>,
    pub record: String,
    pub bob_address: Option<String>,
    pub alice_addresses: Option<String>,
    // pub created_at: u64,
}