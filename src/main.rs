mod classic_request_handling;
mod espresso_transaction;
mod outputs_merkle;
use alloy_primitives::utils::{keccak256, Keccak256};
use alloy_primitives::{FixedBytes, B256};
use async_std::fs::OpenOptions;
use async_std::io::WriteExt;
use base64::{prelude::BASE64_STANDARD, Engine};
use cbor::Decoder;
use chrono::Utc;
use cid::Cid;
use classic_request_handling::{
    add_request_to_database, check_previously_handled_results, handle_database_request,
    query_request_with_the_highest_priority, query_result_from_database,
};
use committable::Committable;
use espresso_transaction::EspressoTransaction;
use futures::channel::oneshot::{channel, Sender};
use futures::StreamExt;
use futures::TryStreamExt;
use hex::FromHexError;
use hyper::body::to_bytes;
use hyper::client::{self, HttpConnector};
use hyper::header::HeaderValue;
use hyper::header::CONTENT_TYPE;
use hyper::service::{make_service_fn, service_fn};
use hyper::Uri;
use hyper::{header, Body, Client, Method, Request, Response, Server, StatusCode};
use hyper_tls::HttpsConnector;
use ipfs_api_backend_hyper::IpfsApi;
use log::info;
use r2d2::Pool;
use regex::Regex;
use rs_car_ipfs::single_file::read_single_file_seek;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::fs::OpenOptions as StdOpenOptions;
use std::io::ErrorKind;
use std::io::Write;
use std::path::Path;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use std::{convert::Infallible, net::SocketAddr};
use std::{env, path::PathBuf};
use tracing::{debug, error, info_span, instrument, trace, warn};
use tracing_subscriber::{fmt, EnvFilter};

const HEIGHT: usize = 63;
#[cfg(feature = "bls_signing")]
use advance_runner::YieldManualReason;
use async_std::fs::File;
use async_std::io::BufReader;
use async_std::io::ReadExt;
use futures::stream;
use r2d2_sqlite::rusqlite::params;
use r2d2_sqlite::SqliteConnectionManager;
#[cfg(feature = "bls_signing")]
use signer_eigen::SignerEigen;
use std::fs::File as OtherFile;
use std::sync::Condvar;
#[derive(Debug, Serialize, Deserialize, Clone)]
enum UploadState {
    UploadStarted,
    UploadInProgress(u64),
    UploadCompleted(u64),
    DagImporting,
    DagImportingComplete,
    DagImportError(String),
    UploadFailed(String),
}

async fn upload_car_file_to_ipfs(
    file_path: &str,
    url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("Starting to upload car file to ipfs: {:?}", file_path);
    let form = reqwest::multipart::Form::new()
        .file("file", file_path)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create form: {}", e);
            format!("Failed to create form: {}", e)
        })?;

    let client = reqwest::Client::new();
    let resp = client.post(url).multipart(form).send().await.map_err(|e| {
        tracing::error!("Failed to send request: {}", e);
        format!("Failed to send request: {}", e)
    })?;
    if resp.status().is_success() {
        tracing::info!("Successfully uploaded file");
        Ok(())
    } else {
        tracing::error!("Failed to upload file");

        Err(format!(
            "Failed to upload file: {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        )
        .into())
    }
}

async fn perform_dag_import(file_path: &Path) -> Result<(), Box<dyn Error>> {
    tracing::info!("Starting DAG import for file: {:?}", file_path);
    let url = "http://127.0.0.1:5001/api/v0/dag/import";

    let file_path_str = match file_path.to_str() {
        Some(s) => s,
        None => return Err("Invalid file path".into()),
    };
    upload_car_file_to_ipfs(file_path_str, url).await
}

fn setup_logging() {
    env_logger::Builder::from_default_env()
        .format(|buf, record| {
            writeln!(
                buf,
                "{} {} [{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.target(),
                record.args()
            )
        })
        .init();

    std::io::stdout().flush().unwrap_or_else(|e| {
        tracing::error!("Failed to flush stdout: {}", e);
        eprintln!("Failed to flush stdout: {}", e);
    });
}

async fn log_and_return(
    response: Response<Body>,
    remote_addr: SocketAddr,
    method: hyper::Method,
    path: String,
    version: hyper::Version,
    start: std::time::Instant,
) -> Result<Response<Body>, Infallible> {
    let content_length = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|hv| hv.to_str().ok())
        .unwrap_or("-");

    let log_message = format!(
        "{} - - \"{}{}{}\" {} {}",
        remote_addr.ip(),
        method,
        path,
        match version {
            hyper::Version::HTTP_10 => " HTTP/1.0",
            hyper::Version::HTTP_11 => " HTTP/1.1",
            hyper::Version::HTTP_2 => " HTTP/2.0",
            hyper::Version::HTTP_3 => " HTTP/3.0",
            _ => " HTTP/?.?",
        },
        response.status().as_u16(),
        content_length
    );

    log::info!("{} ", log_message);

    Ok(response)
}
#[async_std::main]

async fn main() {
    // const UPLOAD_STARTED: &str = "upload_started";
    // const UPLOAD_IN_PROGRESS: &str = "upload_in_progress";
    // const UPLOAD_COMPLETED: &str = "upload_completed";
    // const UPLOAD_FAILED: &str = "upload_failed";

    let subscriber = fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    let main_span = info_span!("main_process", version = env!("CARGO_PKG_VERSION"));
    let _main_guard = main_span.enter();

    tracing::info!("Starting the operator...");

    setup_logging();

    let upload_status_map = Arc::new(Mutex::new(HashMap::<String, UploadState>::new()));

    let upload_status_map_clone = upload_status_map.clone();

    let addr: SocketAddr = ([0, 0, 0, 0], 3033).into();
    let max_threads_number = std::env::var("MAX_THREADS_NUMBER")
        .unwrap_or("3".to_string())
        .parse::<usize>()
        .unwrap();
    let requests: Arc<Mutex<HashMap<i64, Sender<i64>>>> = Arc::new(Mutex::new(HashMap::new()));
    // Counter of active threads
    let thread_count = Arc::new((Mutex::new(0), Condvar::new()));
    // New DB record notifier
    let new_record = Arc::new((Mutex::new(false), Condvar::new()));

    let db_directory = std::env::var("DB_DIRECTORY").unwrap_or(String::from(""));
    let manager = SqliteConnectionManager::file(Path::new(&db_directory).join("requests.db"));
    let pool = r2d2::Pool::new(manager).unwrap();
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    let client = Arc::new(client);

    let sqlite_connect = pool.get().unwrap();
    sqlite_connect
        .query_row("PRAGMA journal_mode = WAL;", [], |_row| Ok(()))
        .expect("Failed to set WAL mode");

    tracing::info!("create table for requests");
    // Create table for requests
    sqlite_connect
        .execute(
            "CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            machine_snapshot_path TEXT NOT NULL,
            payload BLOB NOT NULL,
            no_console_putchar INTEGER CHECK (no_console_putchar IN (1, 0)) NOT NULL,
            priority INTEGER NOT NULL
        );",
            params![],
        )
        .unwrap();

    tracing::info!("Creating table for preimages");
    // Create table for preimages
    sqlite_connect
        .execute(
            "CREATE TABLE IF NOT EXISTS preimages (
            hash_type               INTEGER CHECK( hash_type IN (1, 2, 3) ) NOT NULL,
            hash                    BLOB NOT NULL,
            created_at              INTEGER NOT NULL,
            storage_rent_paid_until INTEGER NOT NULL,
            data                    BLOB NOT NULL
            );",
            params![],
        )
        .unwrap();

    sqlite_connect
        .execute(
            "CREATE INDEX IF NOT EXISTS preimages_hash ON preimages (hash);",
            [],
        )
        .unwrap();

    tracing::info!("create tablae for results");
    // Create table for results
    sqlite_connect
        .execute(
            "
            CREATE TABLE IF NOT EXISTS results (
            id                    INTEGER PRIMARY KEY NOT NULL,
            outputs_vector        BLOB,
            reports_vector        BLOB,
            finish_result         BLOB,
            reason                INTEGER CHECK (reason IN (1, 2, 4)),
            machine_snapshot_path TEXT NOT NULL,
            payload               BLOB NOT NULL,
            no_console_putchar    INTEGER CHECK (no_console_putchar IN (1, 0)) NOT NULL,
            priority              INTEGER,
            error_message         TEXT
            );",
            params![],
        )
        .unwrap();

    thread::spawn({
        let requests = requests.clone();
        let pool: r2d2::Pool<SqliteConnectionManager> = pool.clone();
        let new_record = new_record.clone();

        move || {
            let requests = requests.clone();
            let pool = pool.clone();
            let new_record = new_record.clone();

            loop {
                let sqlite_connection = pool.get().unwrap();
                // Query one record from the DB (choose the one, with the highest priority)

                let classic_request =
                    query_request_with_the_highest_priority(sqlite_connection, new_record.clone());

                let (number_of_active_threads, cvar) = &*thread_count;

                let mut active_threads = number_of_active_threads.lock().unwrap();
                while *active_threads >= max_threads_number {
                    println!("Max thread limit reached. Waiting for the notification.");
                    active_threads = cvar.wait(active_threads).unwrap();
                }
                *active_threads += 1;

                thread::spawn({
                    let requests = requests.clone();
                    let pool = pool.clone();
                    let thread_count = thread_count.clone();
                    move || {
                        let (number_of_active_threads, cvar) = &*thread_count;

                        // Handle request and write the result into DB
                        let sqlite_connection = pool.get().unwrap();

                        async_std::task::block_on(async {
                            handle_database_request(
                                sqlite_connection,
                                &classic_request,
                                requests.clone(),
                            )
                            .await;
                        });
                        *number_of_active_threads.lock().unwrap() -= 1;
                        cvar.notify_one();
                    }
                });
            }
        }
    });

    let service = make_service_fn(|conn: &hyper::server::conn::AddrStream| {
        let requests = requests.clone();
        let pool = pool.clone();
        let new_record = new_record.clone();

        let upload_status_map = upload_status_map_clone.clone();
        let client = client.clone();

        let remote_addr = conn.remote_addr();

        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let client = client.clone();
                let requests = requests.clone();
                let pool = pool.clone();
                let new_record = new_record.clone();
                let upload_status_map = upload_status_map.clone();
                let start = Instant::now();
                let method = req.method().clone();
                let version = req.version();
                let path = req.uri().path().to_owned();
                let remote_addr = remote_addr;
                let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
                async move {
                    let path = req.uri().path().to_owned();
                    tracing::info!("Received request for path: {}", path);
                    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
                    tracing::debug!("Parsed path segments: {:?}", segments);

                    let response = match (req.method().clone(), &segments as &[&str]) {
                        (hyper::Method::POST, ["classic", machine_hash]) => {
                            tracing::info!(
                                "Handling POST request for classic with machine_hash: {}",
                                machine_hash
                            );
                            // Check machine_hash format
                            if let Err(err_response) = check_hash_format(
                            machine_hash,
                            "machine_hash should contain only symbols a-f 0-9 and have length 64",
                        ) {
                            tracing::error!("Invalid machine_hash format: {}", machine_hash);
                            return Ok::<_, Infallible>(err_response);
                        }

                            let mut no_console_putchar =
                                match req.headers().get("X-Console-Putchar") {
                                    Some(_) => false,
                                    None => true,
                                };
                            if std::env::var("ALWAYS_CONSOLE_PUTCHAR").is_ok() {
                                no_console_putchar = false;
                            }
                            tracing::debug!("no_console_putchar value: {}", no_console_putchar);

                            let ruleset_header = req.headers().get("X-Ruleset");
                            let max_ops_header = req.headers().get("X-Max-Ops");

                            let signing_requested = std::env::var("BLS_PRIVATE_KEY").is_ok();

                            let ruleset_bytes = if signing_requested {
                                match signing(ruleset_header) {
                                    Ok(bytes) => bytes,
                                    Err(err_response) => return Ok::<_, Infallible>(err_response),
                                }
                            } else {
                                Vec::new()
                            };

                            let max_ops = match max_ops_header {
                                Some(value) => match value.to_str().unwrap().parse::<i64>() {
                                    Ok(parsed_to_i64_value) => {
                                        tracing::info!(
                                            "Parsed max_ops value successfully: {}",
                                            parsed_to_i64_value
                                        );
                                        parsed_to_i64_value
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to parse max_ops_header: {}", e);
                                        let json_error = serde_json::json!({
                                            "error": e.to_string(),
                                        });
                                        let json_error =
                                            serde_json::to_string(&json_error).unwrap();
                                        let response = Response::builder()
                                            .status(StatusCode::BAD_REQUEST)
                                            .body(Body::from(json_error))
                                            .unwrap();
                                        return Ok::<_, Infallible>(response);
                                    }
                                },
                                None => {
                                    tracing::error!("Missing X-Max-Ops header");
                                    let json_error = serde_json::json!({
                                        "error": "X-Max-Ops header is required ",
                                    });
                                    let json_error = serde_json::to_string(&json_error).unwrap();
                                    let response = Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(json_error))
                                        .unwrap();
                                    return Ok::<_, Infallible>(response);
                                }
                            };
                            let payload = hyper::body::to_bytes(req.into_body())
                                .await
                                .unwrap()
                                .to_vec();
                            tracing::debug!(
                                "Extracted payload from request, size: {}",
                                payload.len()
                            );
                            let priority_fee = 1;

                            let priority = priority_fee * max_ops;
                            tracing::info!("Computed priority: {}", priority);

                            let snapshot_dir = std::env::var("SNAPSHOT_DIR").unwrap();
                            let machine_snapshot_path =
                                Path::new(&snapshot_dir).join(&machine_hash);

                            tracing::debug!("Machine snapshot path: {:?}", machine_snapshot_path);
                            let mut outputs_vector: Option<Vec<(u16, Vec<u8>)>> = None;
                            let mut reports_vector: Option<Vec<(u16, Vec<u8>)>> = None;
                            let mut finish_result: Option<(u16, Vec<u8>)> = None;
                            let mut reason: Option<advance_runner::YieldManualReason> = None;
                            {
                                let sqlite_connection = pool.get().unwrap();
                                tracing::info!(
                                    "Checking previously handled results for snapshot {:?}",
                                    machine_snapshot_path
                                );
                                check_previously_handled_results(
                                    sqlite_connection,
                                    &machine_snapshot_path,
                                    &payload,
                                    &no_console_putchar,
                                    &priority,
                                    &mut outputs_vector,
                                    &mut reports_vector,
                                    &mut finish_result,
                                    &mut reason,
                                );
                            }
                            if outputs_vector.is_none()
                                || reports_vector.is_none()
                                || finish_result.is_none()
                                || reason.is_none()
                            {
                                println!("this request hasn't been handled yet");
                                tracing::warn!(
                                    "Request hasn't been handled yet, adding to database"
                                );
                                let (sender, receiver) = channel::<i64>();
                                {
                                    let sqlite_connection = pool.get().unwrap();
                                    tracing::info!(
                                        "Adding request to database for snapshot {:?}",
                                        machine_snapshot_path
                                    );
                                    add_request_to_database(
                                        sqlite_connection,
                                        requests,
                                        sender,
                                        &machine_snapshot_path,
                                        &payload,
                                        &no_console_putchar,
                                        &priority,
                                    );
                                }
                                {
                                    // Notifies that new record was written to the DB
                                    tracing::info!(
                                        "notifying that the new record was written to the db"
                                    );
                                    let (lock, cvar) = &*new_record;
                                    let mut shared_state = lock.lock().unwrap();
                                    *shared_state = true;
                                    cvar.notify_one();
                                }
                                {
                                    tracing::info!("Waiting for request to be handled...");
                                    // Wait for request to be handled
                                    let id = receiver.await.unwrap();
                                    let sqlite_connection = pool.get().unwrap();
                                    if let Err(error_message) = query_result_from_database(
                                        sqlite_connection,
                                        &id,
                                        &mut outputs_vector,
                                        &mut reports_vector,
                                        &mut finish_result,
                                        &mut reason,
                                    ) {
                                        tracing::error!(
                                            "Failed to fetch result from database: {}",
                                            error_message
                                        );
                                        let json_error = serde_json::json!({
                                            "error": error_message.to_string(),
                                        });
                                        let json_error =
                                            serde_json::to_string(&json_error).unwrap();

                                        let response = Response::builder()
                                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                                            .body(Body::from(json_error))
                                            .unwrap();

                                        return Ok::<_, Infallible>(response);
                                    }
                                }
                            }
                            let mut keccak_outputs = Vec::new();

                            // Generating proofs for each output
                            tracing::info!("Generating proofs for each output");
                            for output in outputs_vector.as_ref().unwrap() {
                                let mut hasher = Keccak256::new();
                                hasher.update(output.1.clone());
                                let output_keccak = B256::from(hasher.finalize());
                                keccak_outputs.push(output_keccak);
                            }

                            let proofs =
                                outputs_merkle::create_proofs(keccak_outputs, HEIGHT).unwrap();
                            if proofs.0.to_vec() != finish_result.as_ref().unwrap().1 {
                                tracing::error!("Merkle proof verification failed: outputs weren't proven successfully");
                                let json_error = serde_json::json!({
                                    "error": "outputs weren't proven successfully",
                                });
                                let json_error = serde_json::to_string(&json_error).unwrap();

                                let response = Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .body(Body::from(json_error))
                                    .unwrap();

                                return Ok::<_, Infallible>(response);
                            }

                            let mut json_response = serde_json::json!({
                               "outputs_callback_vector": &outputs_vector,
                               "reports_callback_vector": &reports_vector,
                            });

                            #[cfg(feature = "nitro_attestation")]
                            {
                                tracing::info!("Starting Nitro attestation process");
                                let finish_result_vec = finish_result.as_ref().unwrap().1.clone();

                                let keccak256_hash = get_data_for_signing(
                                    &ruleset_bytes,
                                    machine_hash,
                                    &payload,
                                    &finish_result_vec,
                                )
                                .unwrap();
                                tracing::debug!(
                                    "Keccak256 hash for Nitro attestation: {:?}",
                                    keccak256_hash
                                );

                                let attestation_doc = BASE64_STANDARD
                                    .encode(get_attestation(keccak256_hash.as_slice()).await);
                                tracing::info!("Generated Nitro attestation document");
                                json_response["attestation_doc"] =
                                    serde_json::json!(&attestation_doc);
                            }

                            #[cfg(feature = "bls_signing")]
                            if signing_requested {
                                tracing::info!("Starting BLS signing process");
                                let bls_private_key_str = std::env::var("BLS_PRIVATE_KEY")
                                    .expect("BLS_PRIVATE_KEY not set");
                                let eigen_signer = SignerEigen::new(bls_private_key_str);

                                let finish_result_vec = finish_result.as_ref().unwrap().1.clone();

                                let keccak256_hash = get_data_for_signing(
                                    &ruleset_bytes,
                                    machine_hash,
                                    &payload,
                                    &finish_result_vec,
                                )
                                .unwrap();
                                tracing::debug!(
                                    "Keccak256 hash for BLS signing: {:?}",
                                    keccak256_hash
                                );

                                let signature_hex = eigen_signer.sign(&keccak256_hash);
                                tracing::info!("BLS signature generated successfully");

                                if reason == Some(YieldManualReason::Accepted) {
                                    json_response["finish_callback"] =
                                        serde_json::json!(finish_result);
                                } else {
                                    json_response["finish_callback"] =
                                        serde_json::json!(finish_result.unwrap().1);
                                }
                                json_response["signature"] =
                                    serde_json::Value::String(signature_hex);
                            }
                            let json_response = serde_json::to_string(&json_response).unwrap();

                            let response = Response::builder()
                                .status(StatusCode::OK)
                                .body(Body::from(json_response))
                                .unwrap();

                            return Ok::<_, Infallible>(response);
                        }
                        (hyper::Method::POST, ["check_preimages_status"]) => {
                            tracing::info!("Received request to check preimage status");
                            let hash_types_and_hashes: Vec<u8> =
                                hyper::body::to_bytes(req.into_body())
                                    .await
                                    .unwrap()
                                    .to_vec();
                            tracing::debug!(
                                "Raw request body size: {}",
                                hash_types_and_hashes.len()
                            );
                            let hash_types_and_hashes =
                                match decode_hash_types_and_hashes(hash_types_and_hashes) {
                                    Ok(data) => {
                                        tracing::info!(
                                            "Successfully decoded hash types and hashes, count: {}",
                                            data.len()
                                        );
                                        data
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            "Failed to decode hash types and hashes: {}",
                                            e
                                        );
                                        let json_error = serde_json::json!({
                                            "error": e.to_string(),
                                        });
                                        let json_error =
                                            serde_json::to_string(&json_error).unwrap();
                                        let response = Response::builder()
                                            .status(StatusCode::BAD_REQUEST)
                                            .body(Body::from(json_error))
                                            .unwrap();
                                        return Ok::<_, Infallible>(response);
                                    }
                                };
                            let mut json_response = Value::Null;
                            for preimage_hash_type_and_hash in hash_types_and_hashes {
                                if preimage_hash_type_and_hash.1.len() > 64 {
                                    tracing::warn!("Hash length exceeds 64 bytes");
                                    json_response[hex::encode(preimage_hash_type_and_hash.1)] = serde_json::json!(
                                        "the hash length should be up to 64 bytes"
                                    );
                                    continue;
                                }

                                let availability_response =
                                    match preimage_available(&pool, &preimage_hash_type_and_hash) {
                                        Ok(true) => {
                                            tracing::info!("Preimage is available for hash");
                                            "available"
                                        }
                                        Ok(false) => {
                                            tracing::info!("Preimage is unavailable for hash");
                                            "unavailable"
                                        }
                                        Err(e) => {
                                            tracing::error!(
                                                "Error checking preimage availability "
                                            );
                                            json_response
                                                [hex::encode(preimage_hash_type_and_hash.1)] =
                                                serde_json::json!(e.to_string());
                                            continue;
                                        }
                                    };
                                tracing::debug!("Encoding preimage status for hash");
                                let data = vec![(
                                    &preimage_hash_type_and_hash.0,
                                    &preimage_hash_type_and_hash.1,
                                    availability_response,
                                )];
                                let mut encoder = cbor::Encoder::from_memory();
                                encoder.encode(&data).unwrap();
                                json_response[hex::encode(preimage_hash_type_and_hash.1)] =
                                    serde_json::json!(hex::encode(encoder.as_bytes()));
                            }
                            let json_response = serde_json::to_string(&json_response).unwrap();

                            tracing::info!("Returning response: {}", json_response);

                            let response = Response::builder()
                                .status(StatusCode::OK)
                                .body(Body::from(json_response))
                                .unwrap();

                            return Ok::<_, Infallible>(response);
                        }
                        (hyper::Method::POST, ["upload_preimages"]) => {
                            tracing::info!("Received request to upload preimages.");
                            let preimages_cbor: Vec<u8> = hyper::body::to_bytes(req.into_body())
                                .await
                                .unwrap()
                                .to_vec();
                            tracing::debug!(
                                "Decoded preimages CBOR: {} bytes",
                                preimages_cbor.len()
                            );
                            let preimages_data = match decode_preimages(preimages_cbor) {
                                Ok(data) => data,
                                Err(e) => {
                                    tracing::error!("Failed to decode preimages: {}", e);
                                    let json_error = serde_json::json!({
                                        "error": e.to_string(),
                                    });
                                    let json_error = serde_json::to_string(&json_error).unwrap();
                                    let response = Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(json_error))
                                        .unwrap();
                                    return Ok::<_, Infallible>(response);
                                }
                            };
                            let mut json_response = Value::Null;
                            for preimage in preimages_data {
                                if preimage.1.len() > 64 {
                                    tracing::warn!("Preimage hash is too long");
                                    json_response[hex::encode(preimage.1)] = serde_json::json!(
                                        "the hash length should be up to 64 bytes"
                                    );
                                    continue;
                                }

                                if preimage.2.len() > (256 * 1024) {
                                    tracing::warn!("Preimage data is too large for hash");
                                    json_response[hex::encode(preimage.1)] =
                                        serde_json::json!("the data is too big");
                                    continue;
                                }

                                if record_exists(&pool, &preimage) {
                                    tracing::info!("Preimage already exists in DB");
                                    json_response[hex::encode(preimage.1)] = serde_json::json!(
                                        "the record already exists in the database"
                                    );
                                    continue;
                                }
                                if let Err(e) =
                                    check_preimage_hash(&preimage.0, &preimage.1, &preimage.2)
                                {
                                    tracing::error!("Hash verification failed: {}", e);
                                    json_response[hex::encode(preimage.1)] =
                                        serde_json::json!(e.to_string());
                                    continue;
                                }
                                if let Err(e) = upload_image_to_sqlite_db(&pool, &preimage) {
                                    tracing::error!("Failed to upload preimage:{} to the DB", e);
                                    json_response[hex::encode(preimage.1)] =
                                        serde_json::json!(e.to_string());
                                    continue;
                                }
                                tracing::info!("Preimage uploaded successfully.");
                                json_response[hex::encode(preimage.1)] =
                                    serde_json::json!("was uploaded successfully");
                            }
                            let json_response = serde_json::to_string(&json_response).unwrap();

                            tracing::info!("Returning response: {}", json_response);
                            let response = Response::builder()
                                .status(StatusCode::OK)
                                .body(Body::from(json_response))
                                .unwrap();

                            return Ok::<_, Infallible>(response);
                        }
                        (hyper::Method::GET, ["get_preimage", hash_type, hash]) => {
                            tracing::info!(
                                "Received request to fetch preimage for hash type: {}, hash: {}",
                                hash_type,
                                hash
                            );
                            let sqlite_connection = pool.get().unwrap();

                            let mut statement = sqlite_connection
                                .prepare(
                                    "SELECT data FROM preimages WHERE hash_type = ? AND hash = ?;",
                                )
                                .unwrap();
                            tracing::debug!("Prepared SQL query.");
                            let mut rows = statement
                                .query(params![hash_type, hex::decode(hash).unwrap()])
                                .unwrap();
                            tracing::debug!("Executed SQL query.");

                            if let Some(statement) = rows.next().unwrap() {
                                tracing::info!("Preimage found in database.");
                                // Query data from the database and encode it to cbor
                                let preimage_data = statement.get::<_, Vec<u8>>(0).unwrap();
                                let response = Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Body::from(preimage_data))
                                    .unwrap();

                                tracing::debug!("Returning preimage data.");
                                return Ok::<_, Infallible>(response);
                            }
                            tracing::warn!("Preimage was not found for hash: {}", hash);
                            let json_error = serde_json::json!({
                                "error": "Preimage wasn't found",
                            });
                            let json_error = serde_json::to_string(&json_error).unwrap();

                            let response = Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Body::from(json_error))
                                .unwrap();

                            return Ok::<_, Infallible>(response);
                        }
                        (hyper::Method::POST, ["ensure", cid_str, machine_hash, size_str]) => {
                            tracing::info!(
                                "Received ensure request with cid: {}, machine_hash: {}, size: {}",
                                cid_str,
                                machine_hash,
                                size_str
                            );
                            // Check machine_hash format
                            if let Err(err_response) = check_hash_format(
                            machine_hash,
                            "machine_hash should contain only symbols a-f 0-9 and have length 64",
                        ) {
                            tracing::warn!("Invalid machine_hash format: {}", machine_hash);
                            return Ok::<_, Infallible>(err_response);
                        }
                            let expected_size: u64 = match size_str.parse::<u64>() {
                                Ok(size) => {
                                    tracing::debug!("Parsed expected size successfully: {}", size);
                                    size
                                }
                                Err(_) => {
                                    tracing::error!(
                                        "Failed to parse size_str as u64: {}",
                                        size_str
                                    );
                                    let json_error = serde_json::json!({
                                        "error": "Invalid size: must be a positive integer",
                                    });
                                    let json_error = serde_json::to_string(&json_error).unwrap();
                                    let response = Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(json_error))
                                        .unwrap();

                                    return Ok::<_, Infallible>(response);
                                }
                            };

                            tracing::info!("Checking snapshot directory environment variable");
                            let snapshot_dir = std::env::var("SNAPSHOT_DIR").unwrap();
                            tracing::debug!("Snapshot directory: {}", snapshot_dir);
                            let machine_dir = format!("{}/{}", snapshot_dir, machine_hash);
                            let lock_file_path = format!("{}.lock", machine_dir);
                            tracing::info!("Checking if machine directory exists: {}", machine_dir);
                            if Path::new(&machine_dir).exists() {
                                if Path::new(&lock_file_path).exists() {
                                    let json_response = serde_json::json!({
                                        "state": "downloading",
                                    });
                                    let json_response =
                                        serde_json::to_string(&json_response).unwrap();

                                    let response = Response::builder()
                                        .status(StatusCode::OK)
                                        .body(Body::from(json_response))
                                        .unwrap();

                                    return Ok::<_, Infallible>(response);
                                } else {
                                    tracing::info!(
                                        "Lock file does not exist, returning ready state."
                                    );
                                    let json_response = serde_json::json!({
                                        "state": "ready",
                                    });
                                    let json_response =
                                        serde_json::to_string(&json_response).unwrap();

                                    let response = Response::builder()
                                        .status(StatusCode::OK)
                                        .body(Body::from(json_response))
                                        .unwrap();

                                    return Ok::<_, Infallible>(response);
                                }
                            } else {
                                tracing::info!(
                                    "Machine directory does not exist, creating lock file: {}",
                                    lock_file_path
                                );
                                match StdOpenOptions::new()
                                    .read(true)
                                    .write(true)
                                    .create_new(true)
                                    .open(&lock_file_path)
                                {
                                    Ok(_) => {
                                        tracing::info!("Lock file created successfully.");
                                        // Clone variables for use inside the async block
                                        let lock_file_path_clone = lock_file_path.clone();
                                        let machine_dir_clone = machine_dir.clone();
                                        let cid_str_clone = cid_str.to_string();
                                        let machine_hash_clone = machine_hash.to_string();
                                        let expected_size_clone = expected_size;

                                        // Spawn the background task
                                        async_std::task::spawn(async move {
                                            tracing::info!(
                                                "Starting background task for downloading"
                                            );
                                            let directory_cid = match cid_str_clone.parse::<Cid>() {
                                                Ok(cid) => {
                                                    tracing::info!(
                                                        "Parsed CID successfully: {}",
                                                        cid
                                                    );
                                                    cid
                                                }
                                                Err(_) => {
                                                    tracing::error!(
                                                        "Invalid CID, removing lock file."
                                                    );
                                                    let _ =
                                                        std::fs::remove_file(&lock_file_path_clone);
                                                    eprintln!("Invalid CID");
                                                    return;
                                                }
                                            };

                                            let ipfs_url = std::env::var("IPFS_URL")
                                                .unwrap_or_else(|_| {
                                                    tracing::warn!(
                                                        "IPFS_URL not set, using the default."
                                                    );
                                                    "http://127.0.0.1:5001".to_string()
                                                });

                                            tracing::info!("Downloading directory from IPFS");
                                            if let Err(err) = dedup_download_directory(
                                                &ipfs_url,
                                                directory_cid,
                                                machine_dir_clone.clone(),
                                                expected_size_clone,
                                            )
                                            .await
                                            {
                                                tracing::error!(
                                                    "Failed to download directory: {}",
                                                    err
                                                );
                                                let _ = std::fs::remove_dir_all(&machine_dir_clone);
                                                let _ = std::fs::remove_file(&lock_file_path_clone);
                                                eprintln!("Failed to download directory: {}", err);
                                                return;
                                            }

                                            let hash_path = format!("{}/hash", machine_dir_clone);
                                            tracing::info!(
                                                "Reading expected hash from: {}",
                                                hash_path
                                            );
                                            let expected_hash_bytes =
                                                match async_std::fs::read(&hash_path).await {
                                                    Ok(bytes) => {
                                                        tracing::info!(
                                                            "Read expected hash successfully."
                                                        );
                                                        bytes
                                                    }
                                                    Err(err) => {
                                                        tracing::error!(
                                                            "Failed to read hash file: {}",
                                                            err
                                                        );
                                                        let _ = std::fs::remove_dir_all(
                                                            &machine_dir_clone,
                                                        );
                                                        let _ = std::fs::remove_file(
                                                            &lock_file_path_clone,
                                                        );
                                                        eprintln!(
                                                            "Failed to read hash file: {}",
                                                            err
                                                        );
                                                        return;
                                                    }
                                                };

                                            let machine_hash_bytes =
                                                match hex::decode(machine_hash_clone) {
                                                    Ok(bytes) => {
                                                        tracing::info!(
                                                            "Decoded machine_hash successfully."
                                                        );
                                                        bytes
                                                    }
                                                    Err(_) => {
                                                        tracing::error!(
                                                            "Invalid machine_hash format."
                                                        );
                                                        let _ = std::fs::remove_dir_all(
                                                            &machine_dir_clone,
                                                        );
                                                        let _ = std::fs::remove_file(
                                                            &lock_file_path_clone,
                                                        );
                                                        eprintln!(
                                                        "Invalid machine_hash: must be valid hex"
                                                    );
                                                        return;
                                                    }
                                                };

                                            if expected_hash_bytes != machine_hash_bytes {
                                                tracing::error!("Hash mismatch: expected does not match provided machine_hash.");
                                                let _ = std::fs::remove_dir_all(&machine_dir_clone);
                                                let _ = std::fs::remove_file(&lock_file_path_clone);
                                                eprintln!("Expected hash from /hash file does not match machine_hash");
                                                return;
                                            }

                                            tracing::info!("Download completed successfully, removing lock file.");
                                            let _ = std::fs::remove_file(&lock_file_path_clone);
                                            println!("Download completed successfully");
                                        });

                                        let json_response = serde_json::json!({
                                            "state": "started_download",
                                        });
                                        let json_response =
                                            serde_json::to_string(&json_response).unwrap();

                                        let response = Response::builder()
                                            .status(StatusCode::OK)
                                            .body(Body::from(json_response))
                                            .unwrap();

                                        return Ok::<_, Infallible>(response);
                                    }
                                    Err(e) => {
                                        if e.kind() == ErrorKind::AlreadyExists {
                                            tracing::info!("Lock file already exists, returning to downloading state.");
                                            let json_response = serde_json::json!({
                                                "state": "downloading",
                                            });
                                            let json_response =
                                                serde_json::to_string(&json_response).unwrap();

                                            let response = Response::builder()
                                                .status(StatusCode::OK)
                                                .body(Body::from(json_response))
                                                .unwrap();

                                            return Ok::<_, Infallible>(response);
                                        } else {
                                            tracing::error!("Failed to create lock file: {}", e);
                                            let json_error = serde_json::json!({
                                                "error": format!("Failed to create lock file: {}", e),
                                            });
                                            let json_error =
                                                serde_json::to_string(&json_error).unwrap();
                                            let response = Response::builder()
                                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                .body(Body::from(json_error))
                                                .unwrap();

                                            return Ok::<_, Infallible>(response);
                                        }
                                    }
                                }
                            }
                        }
                        (hyper::Method::POST, ["upload", upload_id]) => {
                            tracing::info!("Received POST request for upload_id: {}", upload_id);
                            #[derive(Debug, Deserialize)]
                            struct PublishParams {
                                presigned_url: String,
                                upload_id: String,
                            }

                            let whole_body = match hyper::body::to_bytes(req.into_body()).await {
                                Ok(body) => {
                                    tracing::info!(
                                        "Successfully read request body for upload_id: {}",
                                        upload_id
                                    );
                                    body
                                }
                                Err(e) => {
                                    tracing::error!("Failed to read request body: {}", e);
                                    let json_error = json!({
                                        "error": format!("Failed to read request body: {}", e),
                                    });
                                    let response = Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .header("Content-Type", "application/json")
                                        .body(Body::from(json_error.to_string()))
                                        .unwrap();
                                    return Ok(response);
                                }
                            };

                            let publish_params: PublishParams =
                                match serde_json::from_slice(&whole_body) {
                                    Ok(params) => {
                                        tracing::info!(
                                            "Successfully parsed request body for upload_id: {}",
                                            upload_id
                                        );
                                        params
                                    }
                                    Err(e) => {
                                        tracing::error!("Invalid JSON: {}", e);
                                        let json_error = json!({
                                            "error": format!("Invalid JSON: {}", e),
                                        });
                                        let response = Response::builder()
                                            .status(StatusCode::BAD_REQUEST)
                                            .header("Content-Type", "application/json")
                                            .body(Body::from(json_error.to_string()))
                                            .unwrap();
                                        return Ok(response);
                                    }
                                };

                            let presigned_url = publish_params.presigned_url;
                            let upload_id = publish_params.upload_id;

                            tracing::info!("Processing upload_id: {}", upload_id);

                            // is the upload id format check necessary?

                            if let Err(err_response) =
                                check_hash_format(&upload_id, "upload_id invalid format")
                            {
                                tracing::warn!("Invalid upload_id format: {}", upload_id);
                                return Ok(err_response);
                            }

                            let upload_status_map_clone = upload_status_map.clone();

                            let upload_dir = match env::var("UPLOAD_DIR") {
                                Ok(dir) => {
                                    tracing::info!("Using UPLOAD_DIR: {}", dir);
                                    PathBuf::from(dir)
                                }
                                Err(_) => {
                                    tracing::error!("UPLOAD_DIR environment variable is not set");
                                    let json_error = json!({
                                        "error": "UPLOAD_DIR environment variable is not set",
                                    });
                                    let response = Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .header("Content-Type", "application/json")
                                        .body(Body::from(json_error.to_string()))
                                        .unwrap();
                                    return Ok(response);
                                }
                            };
                            {
                                let mut map = upload_status_map.lock().unwrap();

                                if let Some(state) = map.get(&upload_id) {
                                    tracing::info!(
                                        "Found upload state for upload_id: {:?}",
                                        upload_id
                                    );
                                    let json_response = match state {
                                        UploadState::UploadStarted => {
                                            json!({ "state": "upload_started" })
                                        }
                                        UploadState::UploadInProgress(size) => json!({
                                               "state": "upload_in_progress",
                                               "file_size": size
                                        }),
                                        UploadState::UploadCompleted(size) => json!({
                                            "state": "upload_completed",
                                            "file_size": size
                                        }),
                                        UploadState::DagImporting => json!({
                                            "state": "dag_importing",
                                        }),
                                        UploadState::DagImportingComplete => json!({
                                            "state": "dag_importing_complete",
                                        }),
                                        UploadState::DagImportError(err_msg) => json!({
                                            "state": "dag_import_error",
                                            "error": err_msg,
                                        }),
                                        UploadState::UploadFailed(err_msg) => json!({
                                            "state": "upload_failed",
                                            "error": err_msg,
                                        }),
                                    };
                                    let response = Response::builder()
                                        .status(StatusCode::OK)
                                        .header("Content-Type", "application/json")
                                        .body(Body::from(json_response.to_string()))
                                        .unwrap();
                                    return Ok(response);
                                }
                            }

                            let upload_dir_path = upload_dir.join(&upload_id);
                            let lock_file_path = upload_dir_path.with_extension("lock");
                            if upload_dir_path.exists() && !lock_file_path.exists() {
                                tracing::info!("Upload completed for upload_id: {}", upload_id);
                                let json_response = json!({
                                    "state": "upload_completed",
                                });
                                let response = Response::builder()
                                    .status(StatusCode::OK)
                                    .header("Content-Type", "application/json")
                                    .body(Body::from(json_response.to_string()))
                                    .unwrap();
                                return Ok(response);
                            }

                            match OpenOptions::new()
                                .read(true)
                                .write(true)
                                .create_new(true)
                                .open(&lock_file_path)
                                .await
                            {
                                Ok(_) => {
                                    tracing::info!(
                                        "Lock file created successfully at {:?}",
                                        lock_file_path
                                    );
                                    {
                                        let mut map = upload_status_map_clone.lock().unwrap();
                                        map.insert(upload_id.clone(), UploadState::UploadStarted);
                                    }
                                    let upload_status_map_clone = upload_status_map.clone();
                                    let upload_id_clone = upload_id.clone();
                                    let upload_dir_clone = upload_dir.clone();
                                    let presigned_url_clone = presigned_url.clone();
                                    let client_clone = client.clone();

                                    async_std::task::spawn(async move {
                                        {
                                            let mut map = upload_status_map_clone.lock().unwrap();
                                            map.insert(
                                                upload_id_clone.clone(),
                                                UploadState::UploadInProgress(0),
                                            );
                                        }
                                        let upload_dir = upload_dir_clone.join(&upload_id_clone);
                                        tracing::info!(
                                            "Creating upload directory at {:?}",
                                            upload_dir
                                        );
                                        if let Err(e) =
                                            async_std::fs::create_dir_all(&upload_dir).await
                                        {
                                            tracing::error!(
                                                "Failed to create directory {}: {}",
                                                upload_dir.display(),
                                                e
                                            );
                                            eprintln!(
                                                "Failed to create directory {}: {}",
                                                upload_dir.display(),
                                                e
                                            );
                                            {
                                                let mut map =
                                                    upload_status_map_clone.lock().unwrap();
                                                map.insert(
                                                    upload_id_clone.clone(),
                                                    UploadState::UploadFailed(format!(
                                                        "Failed to create directory: {}",
                                                        e
                                                    )),
                                                );
                                            }
                                            let _ = async_std::fs::remove_file(
                                                &upload_dir.with_extension("lock"),
                                            )
                                            .await;
                                            return;
                                        }

                                        let uri = match presigned_url_clone.parse::<Uri>() {
                                            Ok(uri) => uri,
                                            Err(e) => {
                                                tracing::error!(
                                                    "Failed to parse presigned URL: {}",
                                                    e
                                                );
                                                eprintln!("Failed to parse presigned URL: {}", e);
                                                {
                                                    let mut map =
                                                        upload_status_map_clone.lock().unwrap();
                                                    map.insert(
                                                        upload_id_clone.clone(),
                                                        UploadState::UploadFailed(format!(
                                                            "Failed to parse presigned URL: {}",
                                                            e
                                                        )),
                                                    );
                                                }
                                                return;
                                            }
                                        };

                                        tracing::info!("Sending GET request to {:?}", uri);
                                        let response = match client.get(uri).await {
                                            Ok(resp) => resp,
                                            Err(e) => {
                                                tracing::error!(
                                                    "Failed to send the GET request: {}",
                                                    e
                                                );
                                                eprintln!("Failed to send GET request: {}", e);
                                                {
                                                    let mut map =
                                                        upload_status_map_clone.lock().unwrap();
                                                    map.insert(
                                                        upload_id_clone.clone(),
                                                        UploadState::UploadFailed(format!(
                                                            "Failed to send GET request: {}",
                                                            e
                                                        )),
                                                    );
                                                }
                                                let _ = async_std::fs::remove_file(
                                                    &upload_dir.with_extension("lock"),
                                                )
                                                .await;
                                                return;
                                            }
                                        };

                                        if !response.status().is_success() {
                                            tracing::error!(
                                                "Download failed with status: {}",
                                                response.status()
                                            );
                                            let error_msg = format!(
                                                "Download failed with status: {}",
                                                response.status()
                                            );
                                            eprintln!("{}", error_msg);
                                            {
                                                let mut map =
                                                    upload_status_map_clone.lock().unwrap();
                                                map.insert(
                                                    upload_id_clone.clone(),
                                                    UploadState::UploadFailed(error_msg),
                                                );
                                            }
                                            let _ = async_std::fs::remove_file(
                                                &upload_dir.with_extension("lock"),
                                            )
                                            .await;
                                            return;
                                        }
                                        let file_path = upload_dir.join(&upload_id_clone);

                                        let mut file =
                                            match async_std::fs::File::create(&file_path).await {
                                                Ok(f) => f,
                                                Err(e) => {
                                                    tracing::error!("Failed to create file");
                                                    eprintln!(
                                                        "Failed to create file {}: {}",
                                                        file_path.display(),
                                                        e
                                                    );
                                                    {
                                                        let mut map =
                                                            upload_status_map_clone.lock().unwrap();
                                                        map.insert(
                                                            upload_id_clone.clone(),
                                                            UploadState::UploadFailed(format!(
                                                                "Failed to create file: {}",
                                                                e
                                                            )),
                                                        );
                                                    }
                                                    let _ = async_std::fs::remove_file(
                                                        &upload_dir.with_extension("lock"),
                                                    )
                                                    .await;
                                                    return;
                                                }
                                            };

                                        tracing::info!("Starting to stream response body");
                                        let mut stream = response.into_body();

                                        while let Some(Ok(chunk)) = stream.next().await {
                                            let chunk: Vec<u8> = chunk.to_vec();
                                            tracing::info!(
                                                "Received a chunk of {} bytes",
                                                chunk.len()
                                            );
                                            if let Err(e) = file.write_all(&chunk).await {
                                                tracing::error!("Failed to write file: {}", e);
                                                eprintln!(
                                                    "Failed to write to file {}: {}",
                                                    file_path.display(),
                                                    e
                                                );
                                                {
                                                    let mut map =
                                                        upload_status_map_clone.lock().unwrap();
                                                    map.insert(
                                                        upload_id_clone.clone(),
                                                        UploadState::UploadFailed(format!(
                                                            "Failed to write to file: {}",
                                                            e
                                                        )),
                                                    );
                                                }
                                                let _ = async_std::fs::remove_file(
                                                    &upload_dir.with_extension("lock"),
                                                )
                                                .await;
                                                return;
                                            }
                                        }
                                        file.flush().await.unwrap();
                                        drop(file);

                                        tracing::info!(
                                            "Fetching metadata for file: {}",
                                            file_path.display()
                                        );
                                        let file_metadata =
                                            match async_std::fs::metadata(&file_path).await {
                                                Ok(metadata) => {
                                                    tracing::info!(
                                                        "Successfully retrieved metadata for file"
                                                    );
                                                    metadata
                                                }
                                                Err(e) => {
                                                    tracing::error!(
                                                        "Failed to get metadata{}: {}",
                                                        file_path.display(),
                                                        e
                                                    );
                                                    eprintln!(
                                                        "Failed to get metadata for {}: {}",
                                                        file_path.display(),
                                                        e
                                                    );
                                                    {
                                                        let mut map =
                                                            upload_status_map_clone.lock().unwrap();
                                                        map.insert(
                                                            upload_id_clone.clone(),
                                                            UploadState::UploadFailed(format!(
                                                                "Failed to get file metadata: {}",
                                                                e
                                                            )),
                                                        );
                                                    }
                                                    let _ = async_std::fs::remove_file(
                                                        &upload_dir.with_extension("lock"),
                                                    )
                                                    .await;
                                                    return;
                                                }
                                            };
                                        let file_size = file_metadata.len();
                                        tracing::info!(
                                            "File size retrieved: {} bytes for upload_id: {}",
                                            file_size,
                                            upload_id_clone
                                        );

                                        {
                                            let mut map = upload_status_map_clone.lock().unwrap();
                                            map.insert(
                                                upload_id_clone.clone(),
                                                UploadState::UploadCompleted(file_size),
                                            );
                                        }
                                        tracing::info!(
                                            "Upload completed for upload_id: {}",
                                            upload_id_clone
                                        );

                                        {
                                            let mut map = upload_status_map_clone.lock().unwrap();
                                            map.insert(
                                                upload_id_clone.clone(),
                                                UploadState::DagImporting,
                                            );
                                        }
                                        match perform_dag_import(&file_path).await {
                                            Ok(_) => {
                                                let mut map =
                                                    upload_status_map_clone.lock().unwrap();
                                                map.insert(
                                                    upload_id_clone.clone(),
                                                    UploadState::DagImportingComplete,
                                                );
                                                tracing::info!(
                                                    "DAG import completed successfully "
                                                );
                                                println!(
                                                    "DAG import completed successfully for upload_id: {}",
                                                    upload_id_clone
                                                );
                                            }
                                            Err(e) => {
                                                tracing::error!("DAG import failed : {}", e);
                                                let mut map =
                                                    upload_status_map_clone.lock().unwrap();
                                                map.insert(
                                                    upload_id_clone.clone(),
                                                    UploadState::DagImportError(e.to_string()),
                                                );
                                                eprintln!(
                                                    "DAG import failed for upload_id: {}: {}",
                                                    upload_id_clone, e
                                                );
                                            }
                                        }

                                        let _ = async_std::fs::remove_file(
                                            &upload_dir.with_extension("lock"),
                                        )
                                        .await;

                                        tracing::info!(
                                            "Download and DAG import completed successfully for upload_id: {} (Size: {} bytes)",
                                            upload_id_clone, file_size
                                        );
                                        println!(
                                            "Download and DAG import completed successfully for upload_id: {} (Size: {} bytes)",
                                            upload_id_clone, file_size
                                        );
                                    });

                                    let json_response = json!({
                                        "state": "upload_started",
                                    });
                                    let response = Response::builder()
                                        .status(StatusCode::OK)
                                        .header("Content-Type", "application/json")
                                        .body(Body::from(json_response.to_string()))
                                        .unwrap();
                                    return Ok::<_, Infallible>(response);
                                }
                                Err(e) => {
                                    if e.kind() == ErrorKind::AlreadyExists {
                                        tracing::info!("Lock file already exists for upload_id: {}, upload in progress", upload_id);
                                        let json_response = json!({
                                            "state": "upload_in_progress",
                                        });
                                        let response = Response::builder()
                                            .status(StatusCode::OK)
                                            .header("Content-Type", "application/json")
                                            .body(Body::from(json_response.to_string()))
                                            .unwrap();
                                        return Ok::<_, Infallible>(response);
                                    } else {
                                        tracing::error!(
                                            "Failed to create lock file for upload_id:{}",
                                            upload_id
                                        );
                                        let json_error = json!({
                                            "error": format!("Failed to create lock file: {}", e),
                                        });
                                        let response = Response::builder()
                                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                                            .header("Content-Type", "application/json")
                                            .body(Body::from(json_error.to_string()))
                                            .unwrap();
                                        return Ok::<_, Infallible>(response);
                                    }
                                }
                            }
                        }

                        (hyper::Method::GET, ["publish_status", upload_id]) => {
                            let upload_status_map_clone = upload_status_map.clone();
                            let upload_id = upload_id.to_string();

                            tracing::debug!("Checking publish status for upload_id: {}", upload_id);

                            let map = upload_status_map_clone.lock().unwrap();
                            if let Some(state) = map.get(&upload_id) {
                                tracing::info!(
                                    "Fetching status for upload_id: {}, state: {:?}",
                                    upload_id,
                                    state
                                );
                                let json_response = match state {
                                    UploadState::UploadStarted => {
                                        json!({ "state": "upload_started" })
                                    }
                                    UploadState::UploadInProgress(size) => json!({
                                       "state": "upload_in_progress",
                                       "file_size": size
                                    }),
                                    UploadState::UploadCompleted(size) => json!({
                                        "state": "upload_completed",
                                        "file_size": size
                                    }),
                                    UploadState::DagImporting => json!({
                                        "state": "dag_importing"
                                    }),
                                    UploadState::DagImportingComplete => json!({
                                       "state": "dag_importing_complete"
                                    }),
                                    UploadState::DagImportError(err) => json!({
                                        "state": "dag_import_error",
                                        "error": err,
                                    }),
                                    UploadState::UploadFailed(err) => json!({
                                        "state": "upload_failed",
                                        "error": err,
                                    }),
                                };
                                let response = Response::builder()
                                    .status(StatusCode::OK)
                                    .header("Content-Type", "application/json")
                                    .body(Body::from(json_response.to_string()))
                                    .unwrap();
                                Ok::<_, Infallible>(response)
                            } else {
                                tracing::warn!("upload_id not found: {}", upload_id);
                                let json_error = json!({
                                    "error": "upload_id not found",
                                });
                                let response = Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .header("Content-Type", "application/json")
                                    .body(Body::from(json_error.to_string()))
                                    .unwrap();
                                Ok::<_, Infallible>(response)
                            }
                        }

                        (hyper::Method::GET, ["health"]) => {
                            tracing::info!("Health check request received");
                            let json_request = r#"{"healthy": "true"}"#;
                            let response = Response::new(Body::from(json_request));
                            return Ok::<_, Infallible>(response);
                        }
                        _ => {
                            tracing::warn!("Unknown request received");
                            let json_error = serde_json::json!({
                                "error": "unknown request",
                            });
                            let json_error = serde_json::to_string(&json_error).unwrap();
                            let response = Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(json_error))
                                .unwrap();

                            return Ok::<_, Infallible>(response);
                        }
                    };

                    return log_and_return(
                        response.unwrap(),
                        remote_addr,
                        method,
                        path,
                        version,
                        start,
                    )
                    .await;
                }
            }))
        }
    });

    let server = Server::bind(&addr).serve(Box::new(service));
    println!("Server is listening on {}", addr);
    tracing::info!("Server started on {}", addr);
    server.await.unwrap();
}
fn check_preimage_hash(
    hash_type: &u8,
    hash: &Vec<u8>,
    data: &Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!(
        "Checking hash match: hash_type = {}, hash_len = {}, data_len = {}",
        hash_type,
        hash.len(),
        data.len()
    );

    if hash_type == &(HashType::SHA256 as u8) {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        if &result.to_vec() == hash {
            tracing::info!("sha256of the data and the hash successful match");
            return Ok(());
        } else {
            tracing::error!("sha256 of the data and the hash don't match");
            return Err(Box::<dyn std::error::Error>::from(
                "sha256 of the data and the hash don't match",
            ));
        }
    }

    if hash_type == &(HashType::KECCAK256 as u8) {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        let result = hasher.finalize();
        if &result.to_vec() == hash {
            tracing::info!("keccak256 of the data and the hash successful match");
            return Ok(());
        } else {
            tracing::error!("keccak256 of the data and the hash don't match");
            return Err(Box::<dyn std::error::Error>::from(
                "keccak256 of the data and the hash don't match",
            ));
        }
    }
    if hash_type == &(HashType::ESPRESSO_TX as u8) {
        let espresso_transaction: EspressoTransaction = bincode::deserialize(&data)?;
        if &espresso_transaction.commit().into_bits().into_vec() == hash {
            tracing::info!("Espresso transaction hash match successfully");
            return Ok(());
        } else {
            tracing::error!("espresso transaction of the data and the hash don't match");
            return Err(Box::<dyn std::error::Error>::from(
                "espresso transaction of the data and the hash don't match",
            ));
        }
    }
    tracing::error!("Sent hash type isn't supported");
    return Err(Box::<dyn std::error::Error>::from(
        "sent hash type isn't supported",
    ));
}

fn preimage_available(
    pool: &Pool<SqliteConnectionManager>,
    hash_type_and_data: &(u8, Vec<u8>),
) -> Result<bool, Box<dyn std::error::Error>> {
    tracing::info!("Checking preimage availability");
    let sqlite_connection = pool.get()?;

    let mut statement = sqlite_connection.prepare(
        "SELECT storage_rent_paid_until FROM preimages WHERE hash_type = ? AND hash = ?;",
    )?;

    let mut rows = statement.query(params![hash_type_and_data.0, hash_type_and_data.1])?;
    if let Some(statement) = rows.next()? {
        tracing::info!("Database record found");
        return Ok(Utc::now().timestamp() < statement.get::<_, i64>(0)?);
    } else {
        tracing::error!("database record not found");
        return Err(Box::<dyn std::error::Error>::from(
            "database record wasn't found",
        ));
    }
}
fn record_exists(
    pool: &Pool<SqliteConnectionManager>,
    preimage_data: &(u8, Vec<u8>, Vec<u8>),
) -> bool {
    tracing::info!("Checking if record exists in the database");

    let sqlite_connection = pool.get().unwrap();

    let mut statement = sqlite_connection
        .prepare("SELECT * FROM preimages WHERE hash_type = ? AND hash = ? AND data = ?;")
        .unwrap();

    let mut rows = statement
        .query(params![preimage_data.0, preimage_data.1, preimage_data.2])
        .unwrap();
    if let Some(_) = rows.next().unwrap() {
        tracing::info!("Record found in the database");
        return true;
    }
    tracing::info!("Record does not exist in the database");
    return false;
}
fn upload_image_to_sqlite_db(
    pool: &Pool<SqliteConnectionManager>,
    preimage_data: &(u8, Vec<u8>, Vec<u8>),
) -> Result<(), Box<dyn std::error::Error>> {
    let (hash_type, hash, data) = preimage_data;
    tracing::info!(
        "uploading image to sqlite db: hash_type = {}, hash_len = {}, data_len = {}",
        hash_type,
        hash.len(),
        data.len()
    );
    if !(preimage_data.0 == HashType::SHA256 as u8
        || preimage_data.0 == HashType::KECCAK256 as u8
        || preimage_data.0 == HashType::ESPRESSO_TX as u8)
    {
        tracing::error!("sent hash type isn't supported");
        return Err(Box::<dyn std::error::Error>::from(
            "sent hash type isn't supported",
        ));
    }
    let created_at = Utc::now();
    let storage_rent_paid_until = created_at + chrono::Duration::days(365);

    let sqlite_connection = pool.get()?;

    sqlite_connection.execute(
        "INSERT INTO preimages (hash_type, hash, created_at, storage_rent_paid_until, data)
                               VALUES (?, ?, ?, ?, ?)",
        params![
            preimage_data.0,
            preimage_data.1,
            created_at.timestamp(),
            storage_rent_paid_until.timestamp(),
            preimage_data.2
        ],
    )?;
    tracing::info!("sent hash type is successful supported");
    return Ok(());
}

fn decode_hash_types_and_hashes(
    hash_types_and_hashes: Vec<u8>,
) -> Result<Vec<(u8, Vec<u8>)>, Box<dyn std::error::Error>> {
    let mut decoder = Decoder::from_bytes(hash_types_and_hashes);
    let types_and_hashes: Vec<(u8, Vec<u8>)> = decoder.decode().collect::<Result<_, _>>()?;
    return Ok(types_and_hashes);
}
fn decode_preimages(
    preimages_cbor: Vec<u8>,
) -> Result<Vec<(u8, Vec<u8>, Vec<u8>)>, Box<dyn std::error::Error>> {
    let mut decoder = Decoder::from_bytes(preimages_cbor);
    let preimages: Vec<(u8, Vec<u8>, Vec<u8>)> = decoder.decode().collect::<Result<_, _>>()?;
    return Ok(preimages);
}
async fn get_attestation<T: AsRef<[u8]>>(user_data: T) -> Vec<u8> {
    let client = Client::new();

    let uri = "http://localhost:7777/v1/attestation".parse().unwrap();

    let req_data = AttestationUserData {
        user_data: BASE64_STANDARD.encode(user_data),
    };

    let mut req = Request::new(Body::from(serde_json::json!(req_data).to_string()));

    *req.uri_mut() = uri;
    *req.method_mut() = Method::POST;

    let response = client.request(req).await.unwrap();
    to_bytes(response.into_body()).await.unwrap().to_vec()
}
#[derive(Debug, Serialize, Deserialize)]
struct AttestationUserData {
    user_data: String,
}
fn check_hash_format(hash: &str, error_message: &str) -> Result<(), Response<Body>> {
    tracing::info!("Checking hash format for input: {}", hash);
    let hash_regex = Regex::new(r"^[a-f0-9-]+$").unwrap();

    if !hash_regex.is_match(hash) {
        tracing::error!("Invalid hash format detected: {}", hash);
        let json_error = serde_json::json!({
            "error": error_message,
        });
        let json_error = serde_json::to_string(&json_error).unwrap();
        let response = Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from(json_error))
            .unwrap();

        return Err(response);
    }
    return Ok(());
}

fn signing(ruleset_header: Option<&HeaderValue>) -> Result<Vec<u8>, Response<Body>> {
    let ruleset_hex = match ruleset_header {
        Some(value) => value.to_str().unwrap_or_default(),
        None => {
            tracing::error!("Missing X-Ruleset header for signing request");
            let json_error = serde_json::json!({
                "error": "X-Ruleset header is required when signing is requested",
            });
            let json_error = serde_json::to_string(&json_error).unwrap();
            let response = Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(json_error))
                .unwrap();

            return Err(response);
        }
    };

    let ruleset_bytes: Vec<u8> = match hex::decode(ruleset_hex) {
        Ok(bytes) => bytes,
        Err(_) => {
            tracing::error!("Failed to decode ruleset_hex: {}", ruleset_hex);
            let json_error = serde_json::json!({
                "error": "Invalid X-Ruleset header: must be valid hex",
            });
            let json_error = serde_json::to_string(&json_error).unwrap();
            let response = Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(json_error))
                .unwrap();

            return Err(response);
        }
    };

    if ruleset_bytes.len() != 20 {
        let json_error = serde_json::json!({
            "error": "Invalid X-Ruleset header: must decode to 20 bytes",
        });
        let json_error = serde_json::to_string(&json_error).unwrap();
        let response = Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from(json_error))
            .unwrap();

        return Err(response);
    }
    return Ok(ruleset_bytes);
}

async fn dedup_download_directory(
    ipfs_url: &str,
    directory_cid: Cid,
    out_file_path: String,
    max_download: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("Initializing IPFS client for URL: {}", ipfs_url);
    let ipfs_client =
        <ipfs_api_backend_hyper::IpfsClient as ipfs_api_backend_hyper::TryFromUri>::from_str(
            ipfs_url,
        )?;

    tracing::info!("Fetching directory contents for CID: {}", directory_cid);
    let res = ipfs_client
        .ls(&format!("/ipfs/{}", directory_cid.to_string()))
        .await?;

    let first_object = res
        .objects
        .first()
        .ok_or("No objects in IPFS ls response")?;
    tracing::info!("Found {} objects in directory", first_object.links.len());

    let mut current_downloaded = 0u64;

    std::fs::create_dir_all(&out_file_path)?;
    tracing::info!("Created output directory: {}", out_file_path);

    for val in &first_object.links {
        if current_downloaded + val.size > max_download {
            return Err(format!(
                "Downloading file {} would bring us over max download limit",
                val.name
            )
            .into());
        }
        current_downloaded += val.size;

        let req = Request::builder()
            .method("POST")
            .uri(format!("{}/api/v0/dag/export?arg={}", ipfs_url, val.hash))
            .body(Body::empty())
            .unwrap();

        let client = Client::new();
        tracing::info!("Sending request to download file: {}", val.name);

        match client.request(req).await {
            Ok(res) => {
                let mut f = res
                    .into_body()
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Error!"))
                    .into_async_read();

                let file_path = format!("{}/{}", out_file_path, val.name);
                let mut out = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&file_path)
                    .await?;

                read_single_file_seek(&mut f, &mut out, None, Some(val.size as usize)).await?;
            }
            Err(err) => {
                tracing::error!("Error downloading file {}: {}", val.name, err);
                return Err(format!("Error downloading file {}: {}", val.name, err).into());
            }
        }
    }

    Ok(())
}

fn get_data_for_signing(
    ruleset_bytes: &Vec<u8>,
    machine_hash: &str,
    payload: &Vec<u8>,
    finish_result: &Vec<u8>,
) -> Result<FixedBytes<32>, FromHexError> {
    let mut buffer = vec![0u8; 12];
    buffer.extend_from_slice(&ruleset_bytes);

    let machine_hash_bytes = hex::decode(machine_hash)?;

    buffer.extend_from_slice(&machine_hash_bytes);

    let mut hasher = Keccak256::new();
    hasher.update(payload);
    let payload_keccak = hasher.finalize();

    buffer.extend_from_slice(&payload_keccak.to_vec());
    buffer.extend_from_slice(&finish_result);

    Ok(keccak256(&buffer))
}

enum HashType {
    SHA256 = 1,
    KECCAK256 = 2,
    ESPRESSO_TX = 3,
}
