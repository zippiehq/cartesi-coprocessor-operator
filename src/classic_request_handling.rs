use crate::upload_image_to_sqlite_db;
use advance_runner::YieldManualReason;
use advance_runner::{run_advance, Callback};
use alloy_primitives::Keccak256;
use alloy_primitives::{Address, FixedBytes, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rlp::BufMut;
use alloy_rlp::Encodable;
use alloy_rpc_types_eth::{BlockId, BlockTransactionsKind, RpcBlockHash};

use futures_channel::oneshot::Sender;
use hyper::{body::to_bytes, Body, Client, Request};
use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;
use reqwest::Url;
use rusqlite::params;
use serde_json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Condvar;
use std::sync::{Arc, Mutex};
use std::{env::var, error::Error, vec};

const GET_STORAGE_GIO: u32 = 0x27;
const _GET_CODE_GIO: u32 = 0x28; // unused
const GET_ACCOUNT_GIO: u32 = 0x29;
const GET_IMAGE_GIO: u32 = 0x2a;
const LLAMA_COMPLETION_GIO: u32 = 0x2b;
const PUT_IMAGE_KECCAK256_GIO: u32 = 0x2c;
const PUT_IMAGE_SHA256_GIO: u32 = 0x2d;
const PREIMAGE_HINT_GIO: u32 = 0x2e;

const HINT_ETH_CODE_PREIMAGE: u16 = 1;
const HINT_ETH_BLOCK_PREIMAGE: u16 = 2;

pub(crate) fn add_request_to_database(
    sqlite_connection: PooledConnection<SqliteConnectionManager>,
    requests: Arc<Mutex<HashMap<i64, Sender<i64>>>>,
    sender: Sender<i64>,
    machine_snapshot_path: &Path,
    payload: &Vec<u8>,
    no_console_putchar: &bool,
    priority: &i64,
) {
    let no_console_putchar: i64 = match no_console_putchar {
        true => 1,
        false => 0,
    };
    // Write down new request to the DB
    let id: i64  = sqlite_connection.query_row("INSERT INTO requests (machine_snapshot_path, payload, no_console_putchar, priority) VALUES (?, ?, ?, ?) RETURNING id;", params![machine_snapshot_path.to_str(), payload, no_console_putchar, priority], |row| row.get(0)
).unwrap();
    let mut requests = requests.lock().unwrap();
    requests.insert(id, sender);
}
pub(crate) fn check_previously_handled_results(
    sqlite_connection: PooledConnection<SqliteConnectionManager>,
    machine_snapshot_path: &Path,
    payload: &Vec<u8>,
    no_console_putchar: &bool,
    priority: &i64,
    outputs_vector: &mut Option<Vec<(u16, Vec<u8>)>>,
    reports_vector: &mut Option<Vec<(u16, Vec<u8>)>>,
    finish_result: &mut Option<(u16, Vec<u8>)>,
    reason: &mut Option<advance_runner::YieldManualReason>,
) {
    let mut statement = sqlite_connection
    .prepare(
        "SELECT * FROM results WHERE machine_snapshot_path = ? AND payload = ? AND no_console_putchar = ? AND priority = ?;",
    )
    .unwrap();

    let mut rows = statement
        .query(params![
            machine_snapshot_path.to_str(),
            payload,
            no_console_putchar,
            priority
        ])
        .unwrap();
    if let Some(statement) = rows.next().unwrap() {
        if statement.get::<_, String>(9).is_err() {
            println!("this request has been already handled");
            *outputs_vector = bincode::deserialize(&statement.get::<_, Vec<u8>>(1).unwrap()).ok();
            *reports_vector = bincode::deserialize(&statement.get::<_, Vec<u8>>(2).unwrap()).ok();
            *finish_result = bincode::deserialize(&statement.get::<_, Vec<u8>>(3).unwrap()).ok();
            *reason = match &statement.get::<_, i64>(4).unwrap() {
                1 => Some(YieldManualReason::Accepted),
                2 => Some(YieldManualReason::Rejected),
                4 => Some(YieldManualReason::Exception),
                _ => None,
            }
        }
    }
}

pub(crate) fn query_result_from_database(
    sqlite_connection: PooledConnection<SqliteConnectionManager>,
    id: &i64,
    outputs_vector: &mut Option<Vec<(u16, Vec<u8>)>>,
    reports_vector: &mut Option<Vec<(u16, Vec<u8>)>>,
    finish_result: &mut Option<(u16, Vec<u8>)>,
    reason: &mut Option<advance_runner::YieldManualReason>,
) -> Result<(), Box<dyn Error>> {
    // Query the result from the DB
    let mut statement = sqlite_connection
        .prepare("SELECT * FROM results WHERE id = ?")
        .unwrap();

    let mut rows = statement.query([id]).unwrap();

    if let Some(statement) = rows.next().unwrap() {
        match statement.get::<_, String>(9) {
            Err(_) => {
                *outputs_vector =
                    bincode::deserialize(&statement.get::<_, Vec<u8>>(1).unwrap()).ok();
                *reports_vector =
                    bincode::deserialize(&statement.get::<_, Vec<u8>>(2).unwrap()).ok();
                *finish_result =
                    bincode::deserialize(&statement.get::<_, Vec<u8>>(3).unwrap()).ok();
                *reason = match &statement.get::<_, i64>(4).unwrap() {
                    1 => Some(YieldManualReason::Accepted),
                    2 => Some(YieldManualReason::Rejected),
                    4 => Some(YieldManualReason::Exception),
                    _ => None,
                };
                return Ok(());
            }
            Ok(error_message) => {
                return Err(Box::<dyn Error>::from(error_message));
            }
        }
    }
    return Ok(());
}

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
            return ClassicRequest {
                id: statement.get(0).unwrap(),
                machine_snapshot_path: statement.get(1).unwrap(),
                payload: statement.get(2).unwrap(),
                no_console_putchar: statement.get(3).unwrap(),
                priority: statement.get(4).unwrap(),
            };
        } else {
            println!("Waiting for new data to come in");
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

            sqlite_connection.execute("INSERT INTO results (id, outputs_vector, reports_vector, finish_result, reason, machine_snapshot_path, payload, no_console_putchar, priority) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", params![classic_request.id, bincode::serialize(&response.0.outputs_vector).unwrap(), bincode::serialize(&response.0.reports_vector).unwrap(), bincode::serialize(&response.0.finish_result).unwrap(), reason, classic_request.machine_snapshot_path, classic_request.payload, classic_request.no_console_putchar, classic_request.priority]).unwrap();
        }
        Err(err) => {
            sqlite_connection.execute("INSERT INTO results (id, machine_snapshot_path, payload, no_console_putchar, priority, error_message) VALUES (?, ?, ?, ?, ?, ?)", params![classic_request.id, classic_request.machine_snapshot_path, classic_request.payload, classic_request.no_console_putchar, classic_request.priority, err.to_string()]).unwrap();
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

pub(crate) async fn handle_classic(
    classic_request: &ClassicRequest,
) -> Result<(RunAdvanceResponses, YieldManualReason), Box<dyn Error>> {
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
        let mut result: Result<(u16, Vec<u8>), Box<dyn Error>> = Ok((reason, payload.to_vec()));
        outputs_vector.push(result.as_mut().unwrap().clone());
        return result;
    };

    let mut report_callback = |reason: u16, payload: &[u8]| {
        let mut result: Result<(u16, Vec<u8>), Box<dyn Error>> = Ok((reason, payload.to_vec()));
        reports_vector.push(result.as_mut().unwrap().clone());
        return result;
    };
    let mut finish_callback = |reason: u16, payload: &[u8]| {
        let mut result: Result<(u16, Vec<u8>), Box<dyn Error>> = Ok((reason, payload.to_vec()));
        finish_result = result.as_mut().unwrap().clone();
        return result;
    };

    let get_storage: Box<
        dyn Fn(u16, Vec<u8>) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Box<dyn Error>>>>>,
    > = Box::new(|reason: u16, input: Vec<u8>| {
        Box::pin(async move {
            let block_hash: [u8; 32] = input[0..32].try_into()?;
            let address: [u8; 20] = input[32..53].try_into()?;
            let storage_slot: [u8; 32] = input[53..86].try_into()?;

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
                return Err(Box::<dyn Error>::from(
                    "Input shouldn't be larger than 1 mb.",
                ));
            }
            println!("completition input {:?}", input.clone());
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
            if input.len() > (256 * 1024) {
                return Err(Box::<dyn Error>::from("The input is too big"));
            }

            let preimage_hash = {
                let mut hasher = Sha256::new();
                hasher.update(&input);
                hasher.finalize().to_vec()
            };

            let preimage = (1, preimage_hash, input);

            upload_image_to_sqlite_db(&pool, &preimage)?;
            return Ok(vec![]);
        }
    };

    let preimage_hint: Box<
        dyn Fn(u16, Vec<u8>) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Box<dyn Error>>>>>,
    > = Box::new(|hint_type: u16, input: Vec<u8>| {
        Box::pin(async move {
            match hint_type {
                HINT_ETH_CODE_PREIMAGE => {
                    let block_hash: [u8; 32] = input[0..32].try_into()?;
                    let address: [u8; 20] = input[32..52].try_into()?;

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
                    let block_hash: [u8; 32] = input[0..32].try_into()?;

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
                        // Get the RLP encoded block header
                        let mut block_bytes = vec![];
                        block.header.encode(&mut block_bytes);

                        // Calculate keccak256 hash of the RLP encoded block header
                        let mut hasher = Keccak256::new();
                        hasher.update(&block_bytes);
                        let block_hash = hasher.finalize().to_vec();

                        // Store in preimage database with hash type 2 (KECCAK256)
                        let preimage = (2, block_hash.clone(), block_bytes.to_vec());
                        let db_directory =
                            std::env::var("DB_DIRECTORY").unwrap_or(String::from(""));
                        let manager = SqliteConnectionManager::file(
                            Path::new(&db_directory).join("requests.db"),
                        );
                        let pool = r2d2::Pool::new(manager).unwrap();
                        upload_image_to_sqlite_db(&pool, &preimage)?;

                        Ok(vec![])
                    } else {
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
        let reason = run_advance(
            classic_request.machine_snapshot_path.clone(),
            None,
            classic_request.payload.clone(),
            HashMap::new(),
            &mut report_callback,
            &mut output_callback,
            &mut finish_callback,
            callbacks,
            no_console_putchar,
        )
        .await
        .unwrap();

        Ok((
            RunAdvanceResponses {
                outputs_vector,
                reports_vector,
                finish_result,
            },
            reason,
        ))
    } else {
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
    pub machine_snapshot_path: String,
    pub payload: Vec<u8>,
    pub no_console_putchar: i64,
    pub priority: i64,
}
