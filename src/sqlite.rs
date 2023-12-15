// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//! Implementations for stores defined in [super::traits].

use r2d2;
use log::info;
use rusqlite::OptionalExtension;
use rusqlite::params;
use rusqlite::OpenFlags;
use async_trait::async_trait;
use libsignal_protocol::*;
use libsignal_protocol::{SessionStore, IdentityKeyStore, RatchetKeyStore};
use r2d2_sqlite::SqliteConnectionManager;
use libsignal_protocol::SignalProtocolError;
use std::{convert::TryInto, path::Path};
use super::types::{SignalIdentitie, SignalRatchetKey, SignalSession};
pub type Result<T> = std::result::Result<T, SignalProtocolError>;
pub type SqlitePool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;
pub type PooledConnection = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;

const IDENTITY_STORE: &str = r##"
    create table if not exists identity (
        id integer primary key AUTOINCREMENT,
        nextPrekeyId integer,
        registrationId integer,
        device integer,
        address text,
        privateKey text,
        publicKey text,
        createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )"##;

const RATCHET_KEY_STORE: &str = r##"
    create table if not exists ratchet_key (
        id integer primary key AUTOINCREMENT,
        aliceRatchetKeyPublic text,
        address text,
        device integer,
        roomId integer,
        bobRatchetKeyPrivate text,
        ratcheKeyHash text,
        createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )"##;

const SESSION_STORE: &str = r##"
    create table if not exists session (
        id integer primary key AUTOINCREMENT,
        aliceSenderRatchetKey text,
        address text,
        device integer,
        record text,
        bobSenderRatchetKey text,
        bobAddress text,
        aliceAddresses text,
        createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )"##;

    /// Startup DB Pragmas
pub const STARTUP_SQL: &str = r##"
        PRAGMA main.synchronous = NORMAL;
        PRAGMA foreign_keys = ON;
        PRAGMA journal_size_limit = 32768;
        PRAGMA temp_store = 2; -- use memory, not temp files
        PRAGMA main.cache_size = 20000; -- 80MB max cache size per conn
        pragma mmap_size = 0; -- disable mmap (default)
        "##;

pub fn build_pool(
    path: &str
) -> SqlitePool {
    let full_path = Path::new(path);
    let manager = 
        SqliteConnectionManager::file(&full_path)
            .with_flags(OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE)
            .with_init(|c| c.execute_batch(STARTUP_SQL));
    // build use the default config
    let pool: SqlitePool = r2d2::Pool::builder()
        .build(manager)
        .unwrap();
    // retrieve a connection to ensure the startup statements run immediately
    {
        let _ = pool.get();
    }
    pool
}

/// Init sqlite Database
pub async fn init_sqlite(path: &str) -> Result<SqlitePool> {
        let write_pool = build_pool(
            path,
        );
        // create Signal thress state tables
        let conn = 
        write_pool.get()
            .map_err(|err| SignalProtocolError::InvalidArgument(format!("Sqlite not set {:?}", err)))?;
        conn.execute( IDENTITY_STORE, (),)
            .map_err(|err| SignalProtocolError::InvalidArgument(format!("IDENTITY_STORE create err {:?}", err)))?;
        conn.execute( RATCHET_KEY_STORE, (),)
            .map_err(|err| SignalProtocolError::InvalidArgument(format!("RATCHET_KEY_STORE create err {:?}", err)))?;
        conn.execute( SESSION_STORE, (),)
            .map_err(|err| SignalProtocolError::InvalidArgument(format!("SESSION_STORE create err {:?}", err)))?;
    Ok(write_pool) 
}

/// Reference implementation of [traits::IdentityKeyStore].
#[derive(Clone)]
pub struct KeyChatIdentityKeyStore {
    pool: SqlitePool,
    key_pair: IdentityKeyPair, 
    registration_id: u32
}

impl KeyChatIdentityKeyStore {

    pub fn new(pool: SqlitePool, key_pair: IdentityKeyPair, registration_id: u32) -> Self {
        Self {
            pool,
            key_pair,
            registration_id
        }
    }

    /// get identity by address 
    pub async fn get_identity_by_address(&self, address: &str, device_id: &str) -> Result<Option<SignalIdentitie>>{
        let conn = self.pool.get()
                .map_err(|err| SignalProtocolError::InvalidArgument(format!("Can not get conn from get_identity_by_address {:?}", err)))?;
        let mut stmt = conn.prepare(
            r##"select nextPrekeyId, registrationId, address, device, privateKey, publicKey
            from identity where address = ?1 and device = ?2 order by id desc limit 1"##).unwrap();

        let identity =  stmt.query_row(params![address, device_id], |row|{
            Ok(SignalIdentitie {
                next_prekey_id: row.get(0)?,
                registration_id: row.get(1)?,
                address: row.get(2)?,
                device: row.get(3)?,
                private_key: row.get(4)?,
                public_key: row.get(5)?
            })
        })
        .optional()
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("get_identity_by_address identity err {:?}", err)))?;
       Ok(identity)
    }

    pub fn get_identity_key_pair_keys(&self, public_key: &str, private_key: &str) -> Result<IdentityKeyPair> {
        let public_key_vec: Vec<u8> = serde_json::from_str(public_key).unwrap();
        let private_key_vec: Vec<u8> = serde_json::from_str(private_key).unwrap();
        let identity= IdentityKey::decode(&public_key_vec)?;
        let private_key = PrivateKey::deserialize(&private_key_vec)?;
        let id_key_pair = IdentityKeyPair::new(identity, private_key);
        Ok(id_key_pair)
    }

    pub async fn get_identity_key_pair_bak(&self, address: &str, device_id: &str) -> Result<IdentityKeyPair> {
        let identity = self.get_identity_by_address(address, device_id).await.unwrap();
        let id_key_pair = 
            self.get_identity_key_pair_keys(
                &identity.clone().unwrap().public_key, 
                &identity.clone().unwrap().private_key.unwrap()).unwrap();
        Ok(id_key_pair)
    }

    pub async fn get_local_registration_id_bak(&self, address: &str, device_id: &str) -> Result<u32> {
        let identity = self.get_identity_by_address(address, device_id).await.unwrap();
        let registration_id = identity.unwrap().registration_id.unwrap();
        Ok(registration_id)
    }

    /// insert identity
    pub async fn insert_identity(&self, identity: SignalIdentitie) -> Result<()>{
        let conn = self.pool.get()
                .map_err(|err| SignalProtocolError::InvalidArgument(format!("Can not get conn from insert_identity {:?}", err)))?;

        let sql = r##"INSERT INTO identity (nextPrekeyId, registrationId, 
            address, device, privateKey, publicKey) values (?1, ?2, ?3, ?4, ?5, ?6)"##;
        let mut stmt = conn.prepare(sql).unwrap();
        stmt.execute(params![&identity.next_prekey_id, &identity.registration_id, 
            &identity.address, &identity.device, &identity.private_key, &identity.public_key]).unwrap();    
        Ok(())
    }

    pub async fn create_identity(&self, address: &ProtocolAddress, id_key_pair: &IdentityKeyPair) -> Result<bool> {
        let name = address.name();
        let device_id = address.device_id();
        let identity = self.get_identity_by_address(name, &device_id.to_string()).await.unwrap();
        if identity.is_none() {
            let _ = self.insert_identity(
                SignalIdentitie {
                    next_prekey_id: None,
                    registration_id: None, 
                    address: name.to_owned(), 
                    device: device_id.into(),
                    private_key: Some(format!("{:?}", id_key_pair.public_key().serialize())),
                    public_key: format!("{:?}", id_key_pair.private_key().serialize())
            }).await;
            return Ok(true)
        }
        Ok(false)
    }

    pub fn get_identity_public_key(&self, public_key: &str) -> Result<IdentityKey> {
        let public_key_vec: Vec<u8> = serde_json::from_str(public_key).unwrap();
        let identity= IdentityKey::decode(&public_key_vec)?;
        Ok(identity)
    }

    pub async fn delete_identity(&self, address: &str) -> Result<bool> {
        let conn = self.pool.get()
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("Can not get conn from delete_identity {:?}", err)))?;
        let cnt = conn.execute("delete from identity where address = ?1", params![address]).unwrap();
        if cnt > 1 {
            return Ok(true);
        } else {
            return Ok(false);
        }
    }

}


#[async_trait(?Send)]
impl IdentityKeyStore for KeyChatIdentityKeyStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        // let mut csprng = OsRng;
        // let id_key_pair = IdentityKeyPair::generate(&mut csprng);
        // Ok(id_key_pair)
        Ok(self.key_pair)
    }

    async fn get_local_registration_id(&self) -> Result<u32> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool> {
        let name = address.name();
        let device_id = address.device_id();
        let mut signal_identity = self.get_identity_by_address(name, &device_id.to_string()).await.unwrap();
        // new key
        if signal_identity.as_ref().is_none() {
            let _ = self.insert_identity(SignalIdentitie{
                address: name.to_string(),
                device: device_id.into(),
                public_key: format!("{:?}", identity.serialize()),
                private_key: None,
                registration_id: None,
                next_prekey_id: None,
            }).await;
            return Ok(false);
        }
        // if identity change then modify it in db? 
        // overwrite
        if self.get_identity_public_key(&signal_identity.as_ref().unwrap().public_key).unwrap() != *identity {
            signal_identity.as_mut().unwrap().public_key = format!("{:?}", identity.serialize());
            let _= self.insert_identity(signal_identity.unwrap()).await;
            return Ok(true);
        }
        // same key
        Ok(false)
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool> {
        let their_address = address.name();
        let device_id = address.device_id().to_string();
        let signal_identity = self.get_identity_by_address(their_address, &device_id).await.unwrap();
        match direction {
            Direction::Sending => {
                if signal_identity.is_none() {
                    return Ok(true);
                }
                if *identity != self.get_identity_public_key(&signal_identity.as_ref().unwrap().public_key).unwrap() {
                    return Ok(false);
                }
                return Ok(true)
            }
            Direction::Receiving => {
                return Ok(true);
            }
        }
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>> {
        let name = address.name();
        let device_id = address.device_id().to_string();
        let identity = self.get_identity_by_address(name, &device_id).await.unwrap();
        if identity.is_none() {
            return Ok(None);
        }
        let id_key = self.get_identity_public_key(&identity.unwrap().public_key).unwrap();
        Ok(Some(id_key))
    }
}

/// Reference implementation of [traits::SessionStore].
#[derive(Clone)]
pub struct KeyChatSessionStore {
    pool: SqlitePool,
}

impl KeyChatSessionStore {

    /// new 
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool
        }
    }

    /// store session return update flag and alice_addr_previous
    pub async fn store_session_bak(&self, address: &ProtocolAddress, record: &SessionRecord, 
        my_receiver_address: Option<&str>, to_receiver_address: Option<&str>, 
        sender_ratchet_key: Option<&str>) -> Result<(u32, Option<Vec<String>>)> {
        let mut flag:u32 = 0;
        let mut alice_addrs_pre: Option<Vec<String>> = None;
        let name = address.name();
        let device_id = &address.device_id().to_string();
        let mut session = 
        self.get_session(name, device_id).await?;
        if session.is_none() {
            self.insert_session(address, record, my_receiver_address, 
                to_receiver_address, sender_ratchet_key).await?;
            return Ok((0, alice_addrs_pre));
        }
        let session_record = session.clone().unwrap().record;
        let record_to_str = format!("{:?}", record.serialize().unwrap());
        if session_record == record_to_str {
            return Ok((1, alice_addrs_pre));
        }

        let ss = session.as_mut().unwrap();
        ss.record = record_to_str;

        if to_receiver_address.is_some() {
            if ss.bob_sender_ratchet_key.is_none()
            || sender_ratchet_key != ss.bob_sender_ratchet_key.as_deref() {
                // println!("store_session_bak address {:?} to_receiver_address {:?}", address.name(), to_receiver_address);
                ss.bob_address = Some(to_receiver_address.unwrap().to_string());
                ss.bob_sender_ratchet_key = Some(sender_ratchet_key.unwrap().to_string());
                flag = 2;
                self.update_session(false, ss).await?;
            }
        }
        if my_receiver_address.is_some() {
            if ss.alice_addresses.is_none() {
                // println!("store_session_bak address {:?} my_receiver_address {:?}", address.name(), my_receiver_address);
                ss.alice_sender_ratchet_key = Some(sender_ratchet_key.unwrap().to_string());
                ss.alice_addresses = Some(my_receiver_address.unwrap().to_string());
                flag = 3;

            } else if sender_ratchet_key != ss.alice_sender_ratchet_key.as_deref() {
                ss.alice_sender_ratchet_key = Some(sender_ratchet_key.unwrap().to_string());
                let alice_addresses2 = ss.alice_addresses.as_ref().unwrap();
                let mut list: Vec<&str> = alice_addresses2.split(",").collect();
                list.push(my_receiver_address.unwrap());
                ss.alice_addresses = Some(list.join(","));
                flag = 4;
            }
            // only get alice addrs previous when update
            alice_addrs_pre = Some(self.get_alice_addrs_by_identity(name, device_id).await?);
            self.update_session(true, ss).await?;
        }
        Ok((flag, alice_addrs_pre))
}

    pub async fn update_session(&self, is_alice: bool,  session: &SignalSession) -> Result<()> {
        let conn = self.pool.get()
                .map_err(|err| SignalProtocolError::InvalidArgument(format!("Can not get conn from update_session {:?}", err)))?;
        if is_alice {
            let sql = r##"update session set aliceSenderRatchetKey = ?1, aliceAddresses = ?2 
                    , record = ?3 where address = ?4 and device = ?5"##;
                let mut stmt = conn.prepare(sql).unwrap();
                stmt.execute(
                    params![session.alice_sender_ratchet_key, 
                        session.alice_addresses, 
                        session.record,
                        session.address, 
                        session.device]).unwrap();
        } else {
            let sql = r##"update session set bobSenderRatchetKey = ?1, bobAddress = ?2 
                            , record = ?3 where address = ?4 and device = ?5"##;
            let mut stmt = conn.prepare(sql).unwrap();
            stmt.execute(
                params![session.bob_sender_ratchet_key, 
                    session.bob_address, 
                    session.record,
                    session.address, 
                    session.device]).unwrap();
        }
        Ok(())

    }

    /// insert session
    pub async fn insert_session(&self, address: &ProtocolAddress, record: &SessionRecord, 
        my_receiver_address: Option<&str>, to_receiver_address: Option<&str>, 
        sender_ratchet_key: Option<&str>) -> Result<()>{
        let conn = self.pool.get()
                .map_err(|err| SignalProtocolError::InvalidArgument(format!("Can not get conn from insert_session {:?}", err)))?;
        if my_receiver_address.is_none() && to_receiver_address.is_none() {
            let sql = r##"INSERT INTO session (address, device, record) 
                values (?1, ?2, ?3)"##;
            let mut stmt = conn.prepare(sql).unwrap();
            stmt.execute(params![address.name(), address.device_id().to_string(), 
            format!("{:?}", record.serialize().unwrap())]).unwrap();
        }
        if my_receiver_address.is_some() {
            let sql = r##"INSERT INTO session (address, device, record, 
                aliceSenderRatchetKey, aliceAddresses) 
                values (?1, ?2, ?3, ?4, ?5)"##;
            let mut stmt = conn.prepare(sql).unwrap();
            stmt.execute(params![address.name(), address.device_id().to_string(), 
            format!("{:?}", record.serialize().unwrap()), sender_ratchet_key, my_receiver_address]).unwrap();
        }
        if to_receiver_address.is_some() {
            let sql = r##"INSERT INTO session (address, device, record, 
                bobSenderRatchetKey, bobAddress) 
                values (?1, ?2, ?3, ?4, ?5)"##;
            let mut stmt = conn.prepare(sql).unwrap();
            stmt.execute(params![address.name(), address.device_id().to_string(), 
            format!("{:?}", record.serialize().unwrap()), sender_ratchet_key, to_receiver_address]).unwrap();
        }

        Ok(())
    }

    pub async fn get_session(&self, address: &str, device_id: &str) -> Result<Option<SignalSession>>{
        let conn = self.pool.get()
                .map_err(|err| SignalProtocolError::InvalidArgument(format!("Can not get conn from get_session {:?}", err)))?;
        let mut stmt = conn.prepare(
            r##"select aliceSenderRatchetKey, address, device, record, 
            bobSenderRatchetKey, bobAddress, aliceAddresses from session 
            where address = ?1 and device = ?2 order by id desc limit 1"##).unwrap();
        let session = stmt.query_row(params![address, device_id], |row|{
            Ok(SignalSession{
                alice_sender_ratchet_key: row.get(0)?,
                address: row.get(1)?,
                device: row.get(2)?,
                record: row.get(3)?,
                bob_sender_ratchet_key: row.get(4)?,
                bob_address: row.get(5)?,
                alice_addresses: row.get(6)?,
        })
        })
        .optional()
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("get_session err {:?}", err)));
        session
    }

    pub async fn get_all_alice_addrs(&self) -> Result<Vec<String>> {
        let conn = self.pool.get()
                .map_err(|err| SignalProtocolError::InvalidArgument(format!("Can not get conn from get_all_alice_addrs {:?}", err)))?;
        let mut stmt = conn.prepare("select aliceAddresses from session").unwrap();
        let addresses = stmt.query_map([], |row| row.get(0)).unwrap();
        let mut alice_addrs = Vec::new();
        for addr in addresses {
            if addr.is_ok() {
                alice_addrs.push(addr.unwrap());
            }
        }
        Ok(alice_addrs)
    }

    pub async fn get_alice_addrs_by_identity(&self, address: &str, device_id: &str) -> Result<Vec<String>> {
        let conn = self.pool.get()
                .map_err(|err| SignalProtocolError::InvalidArgument(format!("Can not get conn from get_alice_addrs_by_identity {:?}", err)))?;
        let mut stmt = conn.prepare("select aliceAddresses from session where address = ?1 and device = ?2 order by id desc limit 1").unwrap();
        let addresses = stmt.query_map(params![address, device_id], |row| row.get(0)).unwrap();
        let mut alice_addrs = Vec::new();
        for addr in addresses {
            if addr.is_ok() {
                alice_addrs.push(addr.unwrap());
            }
        }
        Ok(alice_addrs)
    }

    pub async fn session_contain_alice_addr(&self, sub_address: &str) -> Result<Option<SignalSession>> {
        let conn = self.pool.get()
                .map_err(|err| SignalProtocolError::InvalidArgument(format!("Can not get conn from session_contain_alice_addr {:?}", err)))?;
        let mut stmt = conn.prepare(
            r##"select aliceSenderRatchetKey, address, device, record, 
                bobSenderRatchetKey, bobAddress, aliceAddresses from session 
                where instr(aliceAddresses, ?) order by id desc limit 1"##).unwrap();
        let session = stmt.query_row(params![sub_address], |row|{
            Ok(SignalSession{
                alice_sender_ratchet_key: row.get(0)?,
                address: row.get(1)?,
                device: row.get(2)?,
                record: row.get(3)?,
                bob_sender_ratchet_key: row.get(4)?,
                bob_address: row.get(5)?,
                alice_addresses: row.get(6)?,
        })
        })
        .optional()
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("session_contain_alice_addr err {:?}", err)));
        session
    }

    pub async fn update_alice_addr(&self, address: &str, device_id: &str, alice_addr: &str) -> Result<bool> {
        let conn = self.pool.get()
                .map_err(|err| SignalProtocolError::InvalidArgument(format!("Can not get conn from update_alice_addr {:?}", err)))?;
        let ex_cnt = conn.execute("update session set aliceAddresses = ?1 where address = ?2 and device = ?3 ", params![alice_addr, address, device_id]).unwrap();
        if ex_cnt > 0 {
            return Ok(true)
        } else {
            return Ok(false)
        }
    }

    pub async fn delete_session(&self, address: &ProtocolAddress) -> Result<()> {
        let name = address.name();
        let device_id = &address.device_id().to_string();
        let session = 
        self.get_session(name, device_id).await?;
        let conn = self.pool.get()
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("Can not get conn from delete_session {:?}", err)))?;
        if session.is_some() {
            conn.execute("delete from session where address = ?1 and device = ?2", params![name, device_id]).unwrap();
        }
        Ok(())
    }

    pub async fn delete_session_by_device_id(&self, device_id: u32) -> Result<bool> {
        let conn = self.pool.get()
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("Can not get conn from delete_session_by_device_id {:?}", err)))?;
        let ex_cnt =  conn.execute("delete from session where device = ?", params![device_id]).unwrap();
        if ex_cnt > 0 {
            return Ok(true)
        } else {
            return Ok(false)
        }
    }

    pub async fn load_session_bak(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>> {
        let name = address.name();
        let device_id = &address.device_id().to_string();
        let session = 
        self.get_session(name, device_id).await?;
        if session.is_some() {
            let record = session.clone().unwrap().record;
            let record_vec:Vec<u8> = serde_json::from_str(&record).unwrap();
            let record = SessionRecord::deserialize(&record_vec);
            return Ok(Some(record.unwrap()));
        } else {
            return Ok(None);
        }
    }

    pub async fn contains_session(&self, address: &ProtocolAddress) -> Result<bool> {
        let name = address.name();
        let device_id = &address.device_id().to_string();
        let session = 
        self.get_session(name, device_id).await?;
        if session.is_none() {
            return Ok(false);
        } 
        let session_record = self.load_session_bak(address).await?;
        if session_record.is_none() {
            return Ok(false);
        }
        // CIPHERTEXT_MESSAGE_CURRENT_VERSION is 3
        let ciphertext_message_current_version = 3;
        let flag = session_record.clone().unwrap().has_sender_chain().unwrap() 
            && session_record.clone().unwrap().session_version().unwrap() 
            == ciphertext_message_current_version;
        Ok(flag)
    }

}


#[async_trait(?Send)]
impl SessionStore for KeyChatSessionStore {
     /// Look up the session corresponding to `address`.
     async fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>>{
        let session = self.load_session_bak(address).await.unwrap();
        Ok(session)
     }
     /// Set the entry for `address` to the value of `record`.
     async fn store_session(
         &mut self,
         address: &ProtocolAddress,
         record: &SessionRecord,
         my_receiver_address: Option<String>,
         to_receiver_address: Option<String>,
         sender_ratchet_key: Option<String>,
     ) -> Result<(u32, Option<Vec<String>>)> {
        let result = self.store_session_bak(address, record, 
            my_receiver_address.as_deref(), 
            to_receiver_address.as_deref(), 
            sender_ratchet_key.as_deref()).await?;
        // println!("The store_session return {:?}", flag);
        Ok(result)
     }
}

/// Reference implementation of [traits::RatchetKeyStore].
#[derive(Clone)]
pub struct KeyChatRatchetKeyStore {
    pool: SqlitePool,
}

impl KeyChatRatchetKeyStore {
    /// new
    pub fn new(pool: SqlitePool,) -> Self {
        Self {
            pool
        }
    }

    pub async fn get_ratchet_key_by_public(&self, ratchet_key: &str) -> Result<Option<SignalRatchetKey>> {
        let conn = self.pool.get()
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("Can not get conn from get_ratchet_key_by_public {:?}", err)))?;
        let sql = r##"select aliceRatchetKeyPublic, address, device, roomId, 
                            bobRatchetKeyPrivate, ratcheKeyHash from ratchet_key 
                            where aliceRatchetKeyPublic = ? order by id desc limit 1"##;
        // println!("get_ratchet_key_by_public ratchet_key {:?}", ratchet_key);
        let mut stmt = conn.prepare(sql).unwrap();
        let ratchet_key = stmt.query_row(params![ratchet_key], |row|{
            let alice_ratchet_key_public = row.get(0)?;
            let address =  row.get(1)?;
            let device:u32 = row.get(2)?;
            let room_id=  row.get(3)?;
            let bob_ratchet_key_private = row.get(4)?;
            let ratche_key_hash =  row.get(5)?;
            Ok(SignalRatchetKey {
                alice_ratchet_key_public,
                room_id,
                address,
                device: device.to_string(),
                bob_ratchet_key_private,
                ratche_key_hash,
            })
        })
        .optional()
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("get_ratchet_key_by_public err {:?}", err)));
        // println!("SignalRatchetKey {:?}", ratchet_key);
        ratchet_key
    }

    /// insert ratchetkey
    pub async fn insert_ratchet_key(&self, ratchet_key: SignalRatchetKey) -> Result<()>{
        let conn = self.pool.get()
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("Can not get conn from insert_ratchet_key {:?}", err)))?;
        let sql = r##"INSERT INTO ratchet_key 
                            (aliceRatchetKeyPublic, address, 
                            device, roomId, bobRatchetKeyPrivate, ratcheKeyHash) 
                            values (?1, ?2, ?3, ?4, ?5, ?6)"##;
        conn.execute(sql, 
            params![&ratchet_key.alice_ratchet_key_public, &ratchet_key.address, 
            &ratchet_key.device, &ratchet_key.room_id, &ratchet_key.bob_ratchet_key_private, &ratchet_key.ratche_key_hash]).unwrap();
        
        Ok(())
    }

     /// identity ratchet_key
     pub async fn delete_by_ratchet_key(&self, ratchet_key: &str) -> Result<()>{
        let conn = self.pool.get()
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("DB not set {:?}", err)))?;
        let cnt_del = conn.execute("delete from ratchet_key where aliceRatchetKeyPublic = ?", params![ratchet_key]).unwrap();
        if cnt_del > 0 {
            info!("delete {} old ratchet_key records for ({:?})", cnt_del, ratchet_key);
        }
        
        Ok(())
    }

     /// identity ratchet_key
     pub async fn delete_by_address_id(&self, id: u32, address: &str, room_id: u32) -> Result<()>{
        let conn = self.pool.get()
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("Can not get conn from delete_by_address_id {:?}", err)))?;
        let cnt_del = conn.execute("delete from ratchet_key where address = ?1 and roomId = ?2 and id <= ?3", params![address, room_id, id]).unwrap();
        if cnt_del > 0 {
            info!("delete {} old ratchet_key records for {:?}, room_id: {}, and id <= {})", cnt_del, address, room_id, id);
        }
        Ok(())
    }

    pub async fn get_max_id_bak(&self, address: &str, room_id: u32) -> Result<Option<u32>> {
        let conn = self.pool.get()
        .map_err(|err| SignalProtocolError::InvalidArgument(format!("Can not get conn from get_max_id_bak {:?}", err)))?;
        let mut stmt = conn.prepare("select max(id) from ratchet_key where address = ?1 and roomId = ?2").unwrap();
        let id = match stmt.query_row(params![address, room_id], |row|{row.get(0)}) {
            Ok(id) => {
                let max_id:u32 = id;
                Some(max_id)
            },
            Err(_err) =>  None,
        };
        Ok(id)
    }

    /// load_rathchet_key_bak
    pub async fn load_rathchet_key_bak(&self, their_ephemeral_public: String) -> Result<String>{
        let ratchet_key = self.get_ratchet_key_by_public(&their_ephemeral_public).await?;
        let private = ratchet_key
            .expect("load_rathchet_key_bak get ratchet_key err.")
            .bob_ratchet_key_private;
        Ok(private)
    }

    /// store_rathchet_key_new
    pub async fn store_rathchet_key_bak(
        &mut self,
        address: &ProtocolAddress,
        room_id: u32,
        their_ephemeral_public: String,
        our_ephemeral_private: String,
    ) -> Result<()>{
        let max_id_option = self.get_max_id_bak(address.name(), room_id).await?;
        let max_id = match max_id_option {
            Some(id) => {
                id
            }
            None => {
                0
            }
        };
        // println!("get_max_id {:?}", max_id);
        if max_id > 2 {
            let _ = self.delete_by_address_id(max_id - 2, address.name(), room_id).await.unwrap();
        }
        let _ = self.insert_ratchet_key(
            SignalRatchetKey { 
                alice_ratchet_key_public: their_ephemeral_public, 
                room_id, 
                address: address.name().to_owned(), 
                device: address.device_id().to_string(), 
                bob_ratchet_key_private: our_ephemeral_private,
                ratche_key_hash: None
            }).await;
        Ok(())
    }
}

#[async_trait(?Send)]
impl RatchetKeyStore for KeyChatRatchetKeyStore {
    /// use load_rathchet_key_bak instead
    fn load_rathchet_key(&self, their_ephemeral_public: String) -> Result<String>{
        let rathchet_key = futures::executor::block_on(async move{
            let rathchet_key = self.load_rathchet_key_bak(their_ephemeral_public).await;
            rathchet_key
        });
        Ok(rathchet_key?)       
    }
    /// use store_rathchet_key_bak instead
    fn store_rathchet_key(
        &mut self,
        address: &ProtocolAddress,
        room_id: u32,
        their_ephemeral_public: String,
        our_ephemeral_private: String,
    ) -> Result<()>{
        // println!("store_rathchet_key");
        futures::executor::block_on(async move{
            let _ = self.store_rathchet_key_bak(address, room_id, their_ephemeral_public, our_ephemeral_private).await;
        });
       
        Ok(())
    }
    /// delete_old_ratchet_key
    async fn delete_old_ratchet_key(&self, id: u32, address: String, room_id: u32) -> Result<()>{
        let _ = self.delete_by_address_id(id, &address, room_id).await;
        Ok(())
    }
    /// get_max_id
    async fn get_max_id(&self, address: &ProtocolAddress, room_id: u32) -> Result<Option<u32>>{
        let max_id = self.get_max_id_bak(address.name(), room_id).await?.unwrap().try_into().unwrap();
        Ok(Some(max_id))
    }
    /// contains_rathchet_key, do not use
    async fn contains_rathchet_key(&self, _their_ephemeral_public: String) -> Result<Option<bool>>{
        Ok(Some(true))
    }
    /// remove_rathchet_key
    async fn remove_rathchet_key(&self, their_ephemeral_public: String) -> Result<()>{
        let _ = self.delete_by_ratchet_key(&their_ephemeral_public).await;
        Ok(())
    }
}

/// Reference implementation of [traits::ProtocolStore].
pub struct KeyChatSignalProtocolStore {
    /// KeyChatSessionStore
    pub session_store: KeyChatSessionStore,
    /// KeyChatIdentityKeyStore
    pub identity_store: KeyChatIdentityKeyStore,
    /// KeyChatRatchetKeyStore
    pub rathchet_key_store: KeyChatRatchetKeyStore,
}

impl KeyChatSignalProtocolStore {
    /// Create an object with the minimal implementation of [traits::ProtocolStore], representing
    /// the given identity `key_pair` along with the separate randomly chosen `registration_id`.
    pub fn new(pool: SqlitePool, key_pair: IdentityKeyPair, registration_id: u32) -> Result<Self> {
        Ok(Self {
            session_store: KeyChatSessionStore::new(pool.clone()),
            identity_store: KeyChatIdentityKeyStore::new(pool.clone(), key_pair, registration_id),
            rathchet_key_store: KeyChatRatchetKeyStore::new(pool.clone()),
        })
    }

    pub fn get_identity_store(&self) -> Result<KeyChatIdentityKeyStore>{
        Ok(self.identity_store.clone())
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for KeyChatSignalProtocolStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        self.identity_store.get_identity_key_pair().await
    }

    async fn get_local_registration_id(&self) -> Result<u32> {
        self.identity_store.get_local_registration_id().await
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool> {
        self.identity_store.save_identity(address, identity).await
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool> {
        self.identity_store
            .is_trusted_identity(address, identity, direction)
            .await
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>> {
        self.identity_store.get_identity(address).await
    }
}


#[async_trait(?Send)]
impl SessionStore for KeyChatSignalProtocolStore {
    async fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>> {
        self.session_store.load_session(address).await
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        my_receiver_address: Option<String>,
        to_receiver_address: Option<String>,
        sender_ratchet_key: Option<String>,
    ) -> Result<(u32, Option<Vec<String>>)> {
        self.session_store.store_session(address, record, my_receiver_address, to_receiver_address, sender_ratchet_key).await
    }
}


#[async_trait(?Send)]
impl RatchetKeyStore for KeyChatSignalProtocolStore {

    fn load_rathchet_key(&self, their_ephemeral_public: String) -> Result<String> {
        self.rathchet_key_store.load_rathchet_key(their_ephemeral_public)
    }

    fn store_rathchet_key(
        &mut self,
        address: &ProtocolAddress,
        room_id: u32,
        their_ephemeral_public: String,
        our_ephemeral_private: String,
    ) -> Result<()> {
        self.rathchet_key_store.store_rathchet_key(address, room_id, their_ephemeral_public, our_ephemeral_private)
    }

    async fn delete_old_ratchet_key(&self, id: u32, address: String, room_id: u32) -> Result<()>{
        self.rathchet_key_store.delete_old_ratchet_key(id, address, room_id).await
    }

    async fn get_max_id(&self, address: &ProtocolAddress, room_id: u32) -> Result<Option<u32>>{
        self.rathchet_key_store.get_max_id(address, room_id).await
    }

    async fn contains_rathchet_key(&self, their_ephemeral_public: String) -> Result<Option<bool>>{
        self.rathchet_key_store.contains_rathchet_key(their_ephemeral_public).await
    }

    async fn remove_rathchet_key(&self, their_ephemeral_public: String) -> Result<()>{
        self.rathchet_key_store.remove_rathchet_key(their_ephemeral_public).await
    }
}


impl ProtocolStore for KeyChatSignalProtocolStore {}