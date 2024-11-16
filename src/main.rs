use advance_runner::run_advance;
mod outputs_merkle;
use alloy_primitives::utils::{keccak256, Keccak256};
use alloy_primitives::{FixedBytes, B256};
use async_std::channel::bounded;
use async_std::fs::OpenOptions;
use base64::{prelude::BASE64_STANDARD, Engine};
use cid::Cid;
use futures::TryStreamExt;
use hex::FromHexError;
use hyper::body::to_bytes;
use hyper::header::HeaderValue;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Method, Request, Response, Server, StatusCode};
use ipfs_api_backend_hyper::IpfsApi;
use regex::Regex;
use rs_car_ipfs::single_file::read_single_file_seek;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions as StdOpenOptions;
use std::io::{Error, ErrorKind};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::{convert::Infallible, net::SocketAddr};
const HEIGHT: usize = 63;

#[cfg(feature = "bls_signing")]
use advance_runner::YieldManualReason;
#[cfg(feature = "bls_signing")]
use sha2::{Digest as Sha2Digest, Sha256};
#[cfg(feature = "bls_signing")]
use signer_eigen::SignerEigen;
#[async_std::main]
async fn main() {
    let addr: SocketAddr = ([0, 0, 0, 0], 3033).into();
    let max_threads_number = std::env::var("MAX_THREADS_NUMBER")
        .unwrap_or("3".to_string())
        .parse::<usize>()
        .unwrap();
    let pool = Arc::new(
        rayon::ThreadPoolBuilder::new()
            .num_threads(max_threads_number)
            .build()
            .unwrap(),
    );
    let service = make_service_fn(|_| {
        let pool = pool.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let pool = pool.clone();

                async move {
                    let path = req.uri().path().to_owned();
                    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
                    match (req.method().clone(), &segments as &[&str]) {
                        (hyper::Method::POST, ["classic", machine_hash]) => {
                            //Check machine_hash format
                            if let Err(err_response) = check_hash_format(
                            machine_hash,
                            "machine_hash should contain only symbols a-f 0-9 and have length 64",
                        ) {
                            return Ok::<_, Infallible>(err_response);
                        }

                            let no_console_putchar = match req.headers().get("X-Console-Putchar") {
                                Some(_) => false,
                                None => true,
                            };

                            let ruleset_header = req.headers().get("X-Ruleset");

                            let signing_requested = std::env::var("BLS_PRIVATE_KEY").is_ok();

                            let ruleset_bytes = if signing_requested {
                                match signing(ruleset_header) {
                                    Ok(bytes) => bytes,
                                    Err(err_response) => return Ok::<_, Infallible>(err_response),
                                }
                            } else {
                                Vec::new()
                            };

                            let payload = hyper::body::to_bytes(req.into_body())
                                .await
                                .unwrap()
                                .to_vec();

                            let snapshot_dir = std::env::var("SNAPSHOT_DIR").unwrap();
                            let mut keccak_outputs = Vec::new();
                            let outputs_vector: Arc<Mutex<Vec<(u16, Vec<u8>)>>> =
                                Arc::new(Mutex::new(Vec::new()));
                            let reports_vector: Arc<Mutex<Vec<(u16, Vec<u8>)>>> =
                                Arc::new(Mutex::new(Vec::new()));
                            let finish_result: Arc<Mutex<(u16, Vec<u8>)>> =
                                Arc::new(Mutex::new((0, vec![0])));
                            let machine_snapshot_path =
                                format!("{}/{}", snapshot_dir, machine_hash);
                            let reason: Arc<Mutex<Option<advance_runner::YieldManualReason>>> =
                                Arc::new(Mutex::new(None));
                            let (sender, receiver) = bounded(1);
                            let outputs_vector_arc_spawn = outputs_vector.clone();
                            let reports_vector_arc_spawn = reports_vector.clone();
                            let finish_result_arc_spawn = finish_result.clone();
                            let payload_arc_spawn = payload.clone();
                            let reason_arc_spawn = reason.clone();

                            pool.spawn_fifo(move || {
                                let outputs_vector = outputs_vector_arc_spawn.clone();
                                let reports_vector = reports_vector_arc_spawn.clone();
                                let finish_result = finish_result_arc_spawn.clone();
                                let reason = reason_arc_spawn.clone();
                                let payload = payload_arc_spawn.clone();
                                let output_callback = |reason: u16, payload: &[u8]| {
                                    let mut result: Result<(u16, Vec<u8>), Error> =
                                        Ok((reason, payload.to_vec()));
                                    outputs_vector
                                        .lock()
                                        .unwrap()
                                        .push(result.as_mut().unwrap().clone());
                                    return result;
                                };

                                let report_callback = |reason: u16, payload: &[u8]| {
                                    let mut result: Result<(u16, Vec<u8>), Error> =
                                        Ok((reason, payload.to_vec()));
                                    reports_vector
                                        .lock()
                                        .unwrap()
                                        .push(result.as_mut().unwrap().clone());
                                    return result;
                                };
                                let finish_callback = |reason: u16, payload: &[u8]| {
                                    let mut result: Result<(u16, Vec<u8>), Error> =
                                        Ok((reason, payload.to_vec()));
                                    *finish_result.lock().unwrap() =
                                        result.as_mut().unwrap().clone();
                                    return result;
                                };
                                *reason.lock().unwrap() = Some(
                                    run_advance(
                                        machine_snapshot_path.clone(),
                                        None,
                                        payload.to_vec(),
                                        HashMap::new(),
                                        &mut Box::new(report_callback),
                                        &mut Box::new(output_callback),
                                        &mut Box::new(finish_callback),
                                        HashMap::new(),
                                        no_console_putchar,
                                    )
                                    .unwrap(),
                                );
                                sender.try_send(true).unwrap();
                            });

                            let _ = receiver.recv().await;

                            //generating proofs for each output
                            for output in &*outputs_vector.lock().unwrap() {
                                let mut hasher = Keccak256::new();
                                hasher.update(output.1.clone());
                                let output_keccak = B256::from(hasher.finalize());
                                keccak_outputs.push(output_keccak);
                            }

                            let proofs =
                                outputs_merkle::create_proofs(keccak_outputs, HEIGHT).unwrap();
                            if proofs.0.to_vec() != finish_result.lock().unwrap().1 {
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
                               "outputs_callback_vector": *outputs_vector,
                               "reports_callback_vector": *reports_vector,
                            });

                            #[cfg(feature = "nitro_attestation")]
                            {
                                let finish_result_vec = finish_result.lock().unwrap().1.clone();

                                let keccak256_hash = get_data_for_signing(
                                    &ruleset_bytes,
                                    machine_hash,
                                    &payload,
                                    &finish_result_vec,
                                )
                                .unwrap();

                                let attestation_doc = BASE64_STANDARD
                                    .encode(get_attestation(keccak256_hash.as_slice()).await);
                                json_response["attestation_doc"] =
                                    serde_json::json!(&attestation_doc);
                            }

                            #[cfg(feature = "bls_signing")]
                            if signing_requested {
                                let bls_private_key_str = std::env::var("BLS_PRIVATE_KEY")
                                    .expect("BLS_PRIVATE_KEY not set");
                                let eigen_signer = SignerEigen::new(bls_private_key_str);

                                let finish_result_vec = finish_result.lock().unwrap().1.clone();

                                let keccak256_hash = get_data_for_signing(
                                    &ruleset_bytes,
                                    machine_hash,
                                    &payload,
                                    &finish_result_vec,
                                )
                                .unwrap();

                                let signature_hex = eigen_signer.sign(&keccak256_hash.as_slice());

                                if *reason.lock().unwrap() == Some(YieldManualReason::Accepted) {
                                    json_response["finish_callback"] =
                                        serde_json::json!(*finish_result);
                                } else {
                                    json_response["finish_callback"] =
                                        serde_json::json!(*finish_result.lock().unwrap().1);
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
                        (hyper::Method::POST, ["ensure", cid_str, machine_hash, size_str]) => {
                            //Check machine_hash format
                            if let Err(err_response) = check_hash_format(
                            machine_hash,
                            "machine_hash should contain only symbols a-f 0-9 and have length 64",
                        ) {
                            return Ok::<_, Infallible>(err_response);
                        }
                            let expected_size: u64 = match size_str.parse::<u64>() {
                                Ok(size) => size,
                                Err(_) => {
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

                            let snapshot_dir = std::env::var("SNAPSHOT_DIR").unwrap();
                            let machine_dir = format!("{}/{}", snapshot_dir, machine_hash);
                            let lock_file_path = format!("{}.lock", machine_dir);

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
                                match StdOpenOptions::new()
                                    .read(true)
                                    .write(true)
                                    .create_new(true)
                                    .open(&lock_file_path)
                                {
                                    Ok(_) => {
                                        // Clone variables for use inside the async block
                                        let lock_file_path_clone = lock_file_path.clone();
                                        let machine_dir_clone = machine_dir.clone();
                                        let cid_str_clone = cid_str.to_string();
                                        let machine_hash_clone = machine_hash.to_string();
                                        let expected_size_clone = expected_size;
                                        let snapshot_dir_clone = snapshot_dir.clone();

                                        // Spawn the background task
                                        async_std::task::spawn(async move {
                                            let directory_cid = match cid_str_clone.parse::<Cid>() {
                                                Ok(cid) => cid,
                                                Err(_) => {
                                                    let _ =
                                                        std::fs::remove_file(&lock_file_path_clone);
                                                    eprintln!("Invalid CID");
                                                    return;
                                                }
                                            };

                                            let ipfs_url = std::env::var("IPFS_URL")
                                                .unwrap_or_else(|_| {
                                                    "http://127.0.0.1:5001".to_string()
                                                });

                                            if let Err(err) = dedup_download_directory(
                                                &ipfs_url,
                                                directory_cid,
                                                machine_dir_clone.clone(),
                                                expected_size_clone,
                                            )
                                            .await
                                            {
                                                let _ = std::fs::remove_dir_all(&machine_dir_clone);
                                                let _ = std::fs::remove_file(&lock_file_path_clone);
                                                eprintln!("Failed to download directory: {}", err);
                                                return;
                                            }

                                            let hash_path = format!("{}/hash", machine_dir_clone);

                                            let expected_hash_bytes =
                                                match async_std::fs::read(&hash_path).await {
                                                    Ok(bytes) => bytes,
                                                    Err(err) => {
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
                                                    Ok(bytes) => bytes,
                                                    Err(_) => {
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
                                                let _ = std::fs::remove_dir_all(&machine_dir_clone);
                                                let _ = std::fs::remove_file(&lock_file_path_clone);
                                                eprintln!("Expected hash from /hash file does not match machine_hash");
                                                return;
                                            }

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
                        (hyper::Method::GET, ["health"]) => {
                            let json_request = r#"{"healthy": "true"}"#;
                            let response = Response::new(Body::from(json_request));
                            return Ok::<_, Infallible>(response);
                        }
                        _ => {
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
                    }
                }
            }))
        }
    });

    let server = Server::bind(&addr).serve(Box::new(service));
    println!("Server is listening on {}", addr);
    server.await.unwrap();
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
    let hash_regex = Regex::new(r"^[a-f0-9]{64}$").unwrap();

    if !hash_regex.is_match(hash) {
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
    let ipfs_client =
        <ipfs_api_backend_hyper::IpfsClient as ipfs_api_backend_hyper::TryFromUri>::from_str(
            ipfs_url,
        )?;
    let res = ipfs_client
        .ls(&format!("/ipfs/{}", directory_cid.to_string()))
        .await?;

    let first_object = res
        .objects
        .first()
        .ok_or("No objects in IPFS ls response")?;

    let mut current_downloaded = 0u64;

    std::fs::create_dir_all(&out_file_path)?;

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
