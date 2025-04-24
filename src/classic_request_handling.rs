use crate::upload_image_to_sqlite_db;
use advance_runner::YieldManualReason;
use advance_runner::{run_advance, Callback};
use alloy_primitives::Keccak256;
use alloy_primitives::{Address, FixedBytes, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rlp::Encodable;
use alloy_rpc_types_eth::{BlockId, BlockTransactionsKind, RpcBlockHash};
use futures_channel::oneshot::Sender;
use hyper::{body::to_bytes, Body, Client, Request};
use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;
use reqwest::Url;
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Condvar;
use std::sync::{Arc, Mutex};
use std::{env::var, error::Error, vec};

#[cfg(feature = "bls_signing")]
use signer_eigen::SignerEigen;

#[cfg(any(feature = "nitro_attestation", feature = "bls_signing"))]
use crate::get_data_for_signing;

#[cfg(feature = "nitro_attestation")]
use crate::get_attestation;
#[cfg(feature = "nitro_attestation")]
use base64::prelude::BASE64_STANDARD;
#[cfg(feature = "nitro_attestation")]
use base64::Engine;

use tracing::{instrument, warn};

const GET_STORAGE_GIO: u32 = 0x27;
const _GET_CODE_GIO: u32 = 0x28; // unused
const GET_ACCOUNT_GIO: u32 = 0x29;
const GET_IMAGE_GIO: u32 = 0x2a;
const LLAMA_COMPLETION_GIO: u32 = 0x2b;
const PUT_IMAGE_KECCAK256_GIO: u32 = 0x2c;
const PUT_IMAGE_SHA256_GIO: u32 = 0x2d;
const PREIMAGE_HINT_GIO: u32 = 0x2e;

const HINT_ETH_CODE_PREIMAGE: u8 = 1;
const HINT_ETH_BLOCK_PREIMAGE: u8 = 2;

pub(crate) fn add_request_to_database(
    sqlite_connection: PooledConnection<SqliteConnectionManager>,
    requests: Arc<Mutex<HashMap<i64, Sender<i64>>>>,
    sender: Option<Sender<i64>>,
    machine_snapshot_path: &Path,
    payload: &Vec<u8>,
    no_console_putchar: &bool,
    priority: &i64,
    ruleset_bytes: &Vec<u8>,
) -> i64 {
    tracing::info!("Starting to add request to database");
    let no_console_putchar: i64 = match no_console_putchar {
        true => 1,
        false => 0,
    };
    tracing::info!(
        "Inserting request into database: machine_snapshot_path={:?}, payload_length={}, no_console_putchar={}, priority={}, ruleset_bytes={:?}",
        machine_snapshot_path, payload.len(), no_console_putchar, priority, ruleset_bytes
    );
    // Write down new request to the DB
    let id: i64  = sqlite_connection.query_row("INSERT INTO requests (machine_snapshot_path, payload, no_console_putchar, priority, ruleset_bytes) VALUES (?, ?, ?, ?, ?) RETURNING id;", params![machine_snapshot_path.to_str(), payload, no_console_putchar, priority, ruleset_bytes], |row| row.get(0)).unwrap();
    let mut requests = requests.lock().unwrap();
    if let Some(sender_channel) = sender {
        requests.insert(id, sender_channel);
    }
    id
}
pub(crate) fn check_previously_handled_results(
    sqlite_connection: PooledConnection<SqliteConnectionManager>,
    machine_snapshot_path: &Path,
    payload: &Vec<u8>,
    no_console_putchar: &bool,
    priority: &i64,
    ruleset_bytes: &Vec<u8>,
) -> Option<i64> {
    tracing::info!("Checking previously handled results for machine_snapshot_path={:?}, payload_length={}, no_console_putchar={}, priority={}",
        machine_snapshot_path, payload.len(), no_console_putchar, priority
    );
    let mut statement = sqlite_connection
    .prepare(
        "SELECT id FROM results WHERE machine_snapshot_path = ? AND payload = ? AND no_console_putchar = ? AND priority = ? AND ruleset_bytes = ?;",
    )
    .unwrap();

    let mut rows = statement
        .query(params![
            machine_snapshot_path.to_str(),
            payload,
            no_console_putchar,
            priority,
            ruleset_bytes
        ])
        .unwrap();
    if let Some(statement) = rows.next().unwrap() {
        return Some(statement.get(0).unwrap());
    }
    return None;
}

pub(crate) fn query_result_from_database(
    sqlite_connection: PooledConnection<SqliteConnectionManager>,
    id: &i64,
) -> Result<ClassicResult, Box<dyn Error>> {
    // Query the result from the DB
    let mut statement = sqlite_connection
        .prepare("SELECT * FROM results WHERE id = ?")
        .unwrap();

    let mut rows = statement.query([id]).unwrap();

    if let Some(statement) = rows.next().unwrap() {
        match statement.get::<_, String>(9) {
            Err(_) => {
                let outputs_vector =
                    bincode::deserialize(&statement.get::<_, Vec<u8>>(1).unwrap()).ok();
                let reports_vector =
                    bincode::deserialize(&statement.get::<_, Vec<u8>>(2).unwrap()).ok();
                let finish_result =
                    bincode::deserialize(&statement.get::<_, Vec<u8>>(3).unwrap()).ok();
                let reason = match &statement.get::<_, i64>(4).unwrap() {
                    1 => Some(YieldManualReason::Accepted),
                    2 => Some(YieldManualReason::Rejected),
                    4 => Some(YieldManualReason::Exception),
                    _ => None,
                };

                return Ok(ClassicResult {
                    outputs_vector,
                    reports_vector,
                    finish_result,
                    #[cfg(feature = "nitro_attestation")]
                    attestation_doc: statement.get::<_, String>(10).unwrap(),
                    #[cfg(feature = "bls_signing")]
                    bls_signature: statement.get::<_, String>(11).unwrap(),
                    reason,
                });
            }
            Ok(error_message) => {
                tracing::error!(id = ?id, error = ?error_message, "Database query error occurred");
                return Err(Box::<dyn Error>::from(error_message));
            }
        }
    }
    return Err(Box::<dyn Error>::from("No queried data found"));
}

#[instrument(skip(sqlite_connection, new_record), fields(waiting_for_data = false))]
pub(crate) fn query_request_with_the_highest_priority(
    sqlite_connection: PooledConnection<SqliteConnectionManager>,
    new_record: Arc<(Mutex<bool>, Condvar)>,
) -> ClassicRequest {
    let mut statement = sqlite_connection
        .prepare(
            "WITH highest_priority_row AS (
                        SELECT *
                        FROM requests
                        ORDER BY priority DESC
                        LIMIT 1
                    )
                    DELETE FROM requests
                    WHERE id IN (SELECT id FROM highest_priority_row)
                    RETURNING *;
            ",
        )
        .unwrap();

    loop {
        let mut rows = statement.query([]).unwrap();
        let res = rows.next().unwrap();
        if let Some(statement) = res {
            let machine_snapshot_path: String = statement.get(1).unwrap();
            return ClassicRequest {
                id: statement.get(0).unwrap(),
                machine_snapshot_path: Path::new(&machine_snapshot_path).to_owned(),
                payload: statement.get(2).unwrap(),
                no_console_putchar: statement.get(3).unwrap(),
                priority: statement.get(4).unwrap(),
                ruleset_bytes: statement.get(5).unwrap(),
            };
        } else {
            tracing::info!("Waiting for new data to comme in");
            let (lock, cvar) = &*new_record;
            let mut record = lock.lock().unwrap();
            while !*record {
                // Waits till new record in the DB
                record = cvar.wait(record).unwrap();
            }

            *record = false;
        }
    }
}

pub(crate) async fn handle_database_request(
    sqlite_connection: PooledConnection<SqliteConnectionManager>,
    classic_request: &ClassicRequest,
    requests: Arc<Mutex<HashMap<i64, Sender<i64>>>>,
) {
    match handle_classic(classic_request).await {
        Ok(response) => {
            let reason = match response.1 {
                YieldManualReason::Accepted => 1,
                YieldManualReason::Rejected => 2,
                YieldManualReason::Exception => 4,
            };

            tracing::debug!(
                request_id = classic_request.id,
                reason = reason,
                "Inserting successful result into database"
            );
            sqlite_connection.execute("INSERT INTO results (id, outputs_vector, reports_vector, finish_result, reason, machine_snapshot_path, payload, no_console_putchar, priority, ruleset_bytes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", params![classic_request.id, bincode::serialize(&response.0.outputs_vector).unwrap(), bincode::serialize(&response.0.reports_vector).unwrap(), bincode::serialize(&response.0.finish_result).unwrap(), reason, classic_request.machine_snapshot_path.to_str().unwrap(), classic_request.payload, classic_request.no_console_putchar, classic_request.priority, classic_request.ruleset_bytes]).unwrap();

            #[cfg(feature = "nitro_attestation")]
            {
                let attestation_doc = get_nitro_attestation(
                    &classic_request.ruleset_bytes,
                    &classic_request
                        .machine_snapshot_path
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap(),
                    &classic_request.payload,
                    response.0.finish_result.1.clone(),
                )
                .await;

                sqlite_connection
                    .execute(
                        "UPDATE results SET attestation_doc = ? WHERE id = ?",
                        params![attestation_doc, classic_request.id],
                    )
                    .unwrap();
            }

            #[cfg(feature = "bls_signing")]
            {
                match std::env::var("BLS_PRIVATE_KEY") {
                    Ok(bls_private_key) => {
                        let signature_bls = sign_bls(
                            response.0.finish_result.0,
                            bls_private_key,
                            &classic_request.ruleset_bytes,
                            &classic_request
                                .machine_snapshot_path
                                .file_name()
                                .unwrap()
                                .to_str()
                                .unwrap(),
                            &classic_request.payload,
                            response.0.finish_result.1.clone(),
                        )
                        .await;
                        sqlite_connection
                            .execute(
                                "UPDATE results SET bls_signature = ? WHERE id = ?",
                                params![signature_bls, classic_request.id],
                            )
                            .unwrap();
                    }
                    Err(_) => {}
                };
            }
        }
        Err(err) => {
            tracing::error!(
                request_id = classic_request.id,
                "Error handling classic request: {}",
                err
            );
            sqlite_connection.execute("INSERT INTO results (id, machine_snapshot_path, payload, no_console_putchar, priority, error_message, ruleset_bytes) VALUES (?, ?, ?, ?, ?, ?, ?)", params![classic_request.id, classic_request.machine_snapshot_path.to_str().unwrap(), classic_request.payload, classic_request.no_console_putchar, classic_request.priority, err.to_string(), classic_request.ruleset_bytes]).unwrap();
        }
    }
    let mut requests: std::sync::MutexGuard<'_, HashMap<i64, Sender<i64>>> =
        requests.lock().unwrap();
    match requests.remove(&classic_request.id) {
        Some(sender) => {
            // Send a signal back to the service request handler, that the result was written into the DB
            let _ = sender.send(classic_request.id);
        }
        None => {}
    }
}

#[cfg(feature = "bls_signing")]
async fn sign_bls(
    finish_reason: u16,
    bls_private_key: String,
    ruleset_bytes: &Vec<u8>,
    machine_hash: &str,
    payload: &Vec<u8>,
    finish_result_vec: Vec<u8>,
) -> String {
    tracing::info!("Starting BLS signing process");
    let eigen_signer = SignerEigen::new(bls_private_key);

    let keccak256_hash = get_data_for_signing(
        finish_reason,
        &ruleset_bytes,
        machine_hash,
        &payload,
        &finish_result_vec,
    )
    .unwrap();
    tracing::debug!("Keccak256 hash for BLS signing: {:?}", keccak256_hash);

    let signature_hex = eigen_signer.sign(&keccak256_hash);
    tracing::info!("BLS signature generated successfully");

    return signature_hex;
}

#[cfg(feature = "nitro_attestation")]
async fn get_nitro_attestation(
    finish_reason: u16,
    ruleset_bytes: &Vec<u8>,
    machine_hash: &str,
    payload: &Vec<u8>,
    finish_result_vec: Vec<u8>,
) -> String {
    tracing::info!("Starting Nitro attestation process");

    let keccak256_hash = get_data_for_signing(
        finish_reason,
        &ruleset_bytes,
        machine_hash,
        &payload,
        &finish_result_vec,
    )
    .unwrap();
    tracing::debug!("Keccak256 hash for Nitro attestation: {:?}", keccak256_hash);

    let attestation_doc = BASE64_STANDARD.encode(get_attestation(keccak256_hash.as_slice()).await);
    tracing::info!("Generated Nitro attestation document");
    return attestation_doc;
}

pub(crate) async fn handle_classic(
    classic_request: &ClassicRequest,
) -> Result<(RunAdvanceResponses, YieldManualReason), Box<dyn Error>> {
    tracing::info!("Handling classic request");
    let no_console_putchar = match classic_request.no_console_putchar {
        0 => false,
        1 => true,
        _ => panic!(
            "no_console_putchar should be 0 or 1: {}",
            classic_request.no_console_putchar
        ),
    };
    let mut outputs_vector: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut reports_vector: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut finish_result: (u16, Vec<u8>) = (0, vec![0]);
    let mut output_callback = |reason: u16, payload: &[u8]| {
        tracing::info!(
            "Output callback called with reason: {}, payload: {:?}",
            reason,
            payload
        );
        let mut result: Result<(u16, Vec<u8>), Box<dyn Error>> = Ok((reason, payload.to_vec()));
        outputs_vector.push(result.as_mut().unwrap().clone());
        return result;
    };

    let mut report_callback = |reason: u16, payload: &[u8]| {
        tracing::info!(
            "Report callback called with reason: {}, payload: {:?}",
            reason,
            payload
        );
        let mut result: Result<(u16, Vec<u8>), Box<dyn Error>> = Ok((reason, payload.to_vec()));
        reports_vector.push(result.as_mut().unwrap().clone());
        return result;
    };

    let mut finish_callback = |reason: u16, payload: &[u8]| {
        tracing::info!(
            "Finish callback called with reason: {}, payload: {:?}",
            reason,
            payload
        );

        let mut result: Result<(u16, Vec<u8>), Box<dyn Error>> = Ok((reason, payload.to_vec()));
        finish_result = result.as_mut().unwrap().clone();
        return result;
    };

    let get_storage: Box<
        dyn Fn(u16, Vec<u8>) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Box<dyn Error>>>>>,
    > = Box::new(|reason: u16, input: Vec<u8>| {
        Box::pin(async move {
            let block_hash: [u8; 32] = input[0..32].try_into()?;
            let address: [u8; 20] = input[32..52].try_into()?;
            let storage_slot: [u8; 32] = input[52..84].try_into()?;

            let ethereum_endpoint = var("ETHEREUM_ENDPOINT")
                .expect("ETHEREUM_ENDPOINT environment variable wasn't set");

            let address = Address::from(address);
            let get_storage_request = ProviderBuilder::new()
                .on_http(Url::parse(&ethereum_endpoint)?)
                .get_storage_at(address, U256::from_be_bytes(storage_slot));

            let storage = get_storage_request
                .block_id(BlockId::Hash(RpcBlockHash::from(FixedBytes::from(
                    &block_hash,
                ))))
                .await?;

            let result: Result<Vec<u8>, Box<dyn Error>> = Ok(storage.to_be_bytes_vec());
            return result;
        })
    });

    let get_account: Box<
        dyn Fn(u16, Vec<u8>) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Box<dyn Error>>>>>,
    > = Box::new(|reason: u16, input: Vec<u8>| {
        Box::pin(async move {
            let block_hash: [u8; 32] = input[0..32].try_into()?;
            let address: [u8; 20] = input[32..53].try_into()?;
            let ethereum_endpoint = var("ETHEREUM_ENDPOINT")
                .expect("ETHEREUM_ENDPOINT environment variable wasn't set");
            let address = Address::from(address);
            let get_account_request = ProviderBuilder::new()
                .on_http(Url::parse(&ethereum_endpoint)?)
                .get_account(address);
            let account = get_account_request
                .block_id(BlockId::Hash(RpcBlockHash::from(FixedBytes::from(
                    &block_hash,
                ))))
                .await?;

            let result: Result<Vec<u8>, Box<dyn Error>> = Ok([
                account.balance.to_be_bytes_vec(),
                account.nonce.to_be_bytes().to_vec(),
                account.code_hash.to_vec(),
                account.storage_root.to_vec(),
            ]
            .concat());
            return result;
        })
    });

    let db_directory = std::env::var("DB_DIRECTORY").unwrap_or(String::from(""));
    let manager = SqliteConnectionManager::file(Path::new(&db_directory).join("requests.db"));
    let pool = r2d2::Pool::new(manager).unwrap();

    let get_preimage = {
        let pool: r2d2::Pool<SqliteConnectionManager> = pool.clone();
        move |reason: u16, mut input: Vec<u8>| -> Result<Vec<u8>, Box<dyn Error>> {
            tracing::info!(
                "get_preimage called with reason: {}, input length: {}",
                reason,
                input.len()
            );
            let sqlite_connection = pool.get()?;
            let hash_type = input.remove(0);
            let data = input;
            let mut statement = sqlite_connection
                .prepare("SELECT * FROM preimages WHERE hash_type = ? AND hash = ?;")?;

            let mut rows = statement.query(params![hash_type, data])?;

            if let Some(statement) = rows.next()? {
                // Query data from the database and return it
                return Ok(statement.get::<_, Vec<u8>>(4)?);
            }
            tracing::error!("No matching entry found in database.");
            return Err(Box::<dyn Error>::from(
                "No data found with such hash and hash type",
            ));
        }
    };

    let completion: Box<
        dyn Fn(u16, Vec<u8>) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Box<dyn Error>>>>>,
    > = Box::new(|reason: u16, input: Vec<u8>| {
        Box::pin(async move {
            if input.len() > 0x100000 {
                tracing::error!("Input shouldn't be larger than 1 mb.");
                return Err(Box::<dyn Error>::from(
                    "Input shouldn't be larger than 1 mb.",
                ));
            }
            tracing::debug!("completition input {:?}", input.clone());
            let llama_server_address = var("LLAMA_SERVER")?;
            let completion_http_request = Request::builder()
                .method("POST")
                .uri(format!("{}/v1/chat/completions", llama_server_address))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer no-key")
                .body(Body::from(input))
                .unwrap();

            let http_client = Client::new();

            match http_client.request(completion_http_request).await {
                Ok(completion_response) => {
                    return Ok(to_bytes(completion_response.into_body()).await?.to_vec());
                }
                Err(e) => {
                    tracing::error!("Error querying completion request: {:?}", e);
                    return Err(Box::<dyn Error>::from(format!(
                        "Error querying completion request: {:?}",
                        e
                    )));
                }
            }
        })
    });

    let put_image_keccak256 = {
        let pool: r2d2::Pool<SqliteConnectionManager> = pool.clone();
        move |reason: u16, input: Vec<u8>| -> Result<Vec<u8>, Box<dyn Error>> {
            if input.len() > (256 * 1024) {
                tracing::error!("The input is too big");
                return Err(Box::<dyn Error>::from("The input is too big"));
            }

            let preimage_hash = {
                let mut hasher = Keccak256::new();
                hasher.update(&input);
                hasher.finalize().to_vec()
            };

            let preimage = (2, preimage_hash, input);

            upload_image_to_sqlite_db(&pool, &preimage)?;
            return Ok(vec![]);
        }
    };

    let put_image_sha256 = {
        let pool: r2d2::Pool<SqliteConnectionManager> = pool.clone();
        move |reason: u16, input: Vec<u8>| -> Result<Vec<u8>, Box<dyn Error>> {
            tracing::info!(
                "put_image_sha256 called with reason: {}, input size: {}",
                reason,
                input.len()
            );
            if input.len() > (256 * 1024) {
                tracing::error!("The input is too big: {} bytes", input.len());
                return Err(Box::<dyn Error>::from("The input is too big"));
            }

            let preimage_hash = {
                let mut hasher = Sha256::new();
                hasher.update(&input);
                hasher.finalize().to_vec()
            };

            let preimage = (1, preimage_hash, input);

            upload_image_to_sqlite_db(&pool, &preimage)?;
            tracing::info!("Preimage successfully uploaded to database.");
            return Ok(vec![]);
        }
    };

    let preimage_hint: Box<
        dyn Fn(u16, Vec<u8>) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Box<dyn Error>>>>>,
    > = Box::new(|reason: u16, input: Vec<u8>| {
        Box::pin(async move {
            let hint_type: u8 = input[0];
            match hint_type {
                HINT_ETH_CODE_PREIMAGE => {
                    let block_hash: [u8; 32] = input[1..33].try_into()?;
                    let address: [u8; 20] = input[33..53].try_into()?;

                    let ethereum_endpoint = var("ETHEREUM_ENDPOINT")
                        .expect("ETHEREUM_ENDPOINT environment variable wasn't set");
                    let address = Address::from(address);
                    let get_code_request = ProviderBuilder::new()
                        .on_http(Url::parse(&ethereum_endpoint)?)
                        .get_code_at(address);
                    let code_bytes = get_code_request
                        .block_id(BlockId::Hash(RpcBlockHash::from(FixedBytes::from(
                            &block_hash,
                        ))))
                        .await?;

                    // Calculate keccak256 hash of the code
                    let mut hasher = Keccak256::new();
                    hasher.update(&code_bytes);
                    let code_hash = hasher.finalize().to_vec();

                    // Store in preimage database with hash type 2 (KECCAK256)
                    let preimage = (2, code_hash.clone(), code_bytes.to_vec());
                    let db_directory = std::env::var("DB_DIRECTORY").unwrap_or(String::from(""));
                    let manager =
                        SqliteConnectionManager::file(Path::new(&db_directory).join("requests.db"));
                    let pool = r2d2::Pool::new(manager).unwrap();
                    upload_image_to_sqlite_db(&pool, &preimage)?;

                    Ok(vec![])
                }
                HINT_ETH_BLOCK_PREIMAGE => {
                    let block_hash: [u8; 32] = input[1..33].try_into()?;

                    let ethereum_endpoint = var("ETHEREUM_ENDPOINT")
                        .expect("ETHEREUM_ENDPOINT environment variable wasn't set");
                    let block = ProviderBuilder::new()
                        .on_http(Url::parse(&ethereum_endpoint)?)
                        .get_block(
                            BlockId::Hash(RpcBlockHash::from(FixedBytes::from(&block_hash))),
                            BlockTransactionsKind::Hashes,
                        )
                        .await?;

                    if let Some(block) = block {
                        tracing::info!("Get the RLP encoded block header");
                        // Get the RLP encoded block header
                        let mut block_bytes = vec![];
                        block.header.encode(&mut block_bytes);

                        // Calculate keccak256 hash of the RLP encoded block header
                        let mut hasher = Keccak256::new();
                        hasher.update(&block_bytes);
                        let block_hash = hasher.finalize().to_vec();

                        tracing::info!("Store in preimage database with hash type 2 (KECCAK256)");
                        // Store in preimage database with hash type 2 (KECCAK256)
                        let preimage = (2, block_hash.clone(), block_bytes.to_vec());
                        let db_directory =
                            std::env::var("DB_DIRECTORY").unwrap_or(String::from(""));
                        let manager = SqliteConnectionManager::file(
                            Path::new(&db_directory).join("requests.db"),
                        );
                        let pool = r2d2::Pool::new(manager).unwrap();
                        upload_image_to_sqlite_db(&pool, &preimage)?;
                        tracing::info!("Preimage successfully uploaded to database.");

                        Ok(vec![])
                    } else {
                        tracing::error!("Block not found");
                        Err(Box::<dyn Error>::from("Block not found"))
                    }
                }
                _ => Err(Box::<dyn Error>::from("Unsupported hint type")),
            }
        })
    });

    let mut callbacks = HashMap::new();
    callbacks.insert(GET_STORAGE_GIO, Callback::Async(get_storage));
    callbacks.insert(GET_ACCOUNT_GIO, Callback::Async(get_account));
    callbacks.insert(GET_IMAGE_GIO, Callback::Sync(Box::new(get_preimage)));
    callbacks.insert(PREIMAGE_HINT_GIO, Callback::Async(preimage_hint));

    // Only include LLAMA completion if NO_LLAMA is not set
    if std::env::var("NO_LLAMA").is_err() {
        callbacks.insert(LLAMA_COMPLETION_GIO, Callback::Async(completion));
    }

    callbacks.insert(
        PUT_IMAGE_KECCAK256_GIO,
        Callback::Sync(Box::new(put_image_keccak256)),
    );
    callbacks.insert(
        PUT_IMAGE_SHA256_GIO,
        Callback::Sync(Box::new(put_image_sha256)),
    );

    let machine_snapshot_path = Path::new(&classic_request.machine_snapshot_path);
    if machine_snapshot_path.join("config.json").exists() {
        tracing::info!("Found config.json, proceeding with run_advance");
        let reason = run_advance(
            String::from(classic_request.machine_snapshot_path.to_str().unwrap()),
            None,
            classic_request.payload.clone(),
            HashMap::new(),
            &mut report_callback,
            &mut output_callback,
            &mut finish_callback,
            callbacks,
            no_console_putchar,
        )
        .await?;

        Ok((
            RunAdvanceResponses {
                outputs_vector,
                reports_vector,
                finish_result,
            },
            reason,
        ))
    } else {
        tracing::error!(
            "No config.json file was found in {:?}",
            machine_snapshot_path
        );
        return Err(Box::<dyn Error>::from(format!(
            "No config.json file was found in: {:?}",
            machine_snapshot_path
        )));
    }
}

#[derive(Debug)]
pub(crate) struct RunAdvanceResponses {
    pub outputs_vector: Vec<(u16, Vec<u8>)>,
    pub reports_vector: Vec<(u16, Vec<u8>)>,
    pub finish_result: (u16, Vec<u8>),
}

pub(crate) struct ClassicRequest {
    pub id: i64,
    pub machine_snapshot_path: PathBuf,
    pub payload: Vec<u8>,
    pub no_console_putchar: i64,
    pub priority: i64,
    pub ruleset_bytes: Vec<u8>,
}

pub struct ClassicResult {
    pub outputs_vector: Option<Vec<(u16, Vec<u8>)>>,
    pub reports_vector: Option<Vec<(u16, Vec<u8>)>>,
    pub finish_result: Option<(u16, Vec<u8>)>,
    #[cfg(feature = "nitro_attestation")]
    pub attestation_doc: String,
    #[cfg(feature = "bls_signing")]
    pub bls_signature: String,
    pub reason: Option<advance_runner::YieldManualReason>,
}
