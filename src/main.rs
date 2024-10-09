use advance_runner::run_advance;
use async_std::fs::OpenOptions;
use cid::Cid;
use futures::TryStreamExt;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server, StatusCode};
use ipfs_api_backend_hyper::IpfsApi;
use regex::Regex;
use rs_car_ipfs::single_file::read_single_file_seek;
use sha3::{Digest, Keccak256};
use std::fs::OpenOptions as StdOpenOptions;
use std::io::ErrorKind;
use std::path::Path;
use std::{
    collections::HashMap,
    convert::Infallible,
    fs::File,
    io::{Error, Read},
    net::SocketAddr,
};
const CHUNK_SIZE: usize = 131072;

#[cfg(feature = "bls_signing")]
use ark_serialize::CanonicalSerialize;
#[cfg(feature = "bls_signing")]
use eigen_crypto_bls::{BlsKeyPair, Signature};
#[cfg(feature = "bls_signing")]
use sha2::{Digest as Sha2Digest, Sha256};

#[async_std::main]
async fn main() {
    let addr: SocketAddr = ([0, 0, 0, 0], 3033).into();
    let service = make_service_fn(|_| async move {
        Ok::<_, Infallible>(service_fn(move |req| async move {
            let path = req.uri().path().to_owned();
            let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

            match (req.method().clone(), &segments as &[&str]) {
                (hyper::Method::POST, ["lambda", machine_hash, lambda_hash]) => {
                    let hash_regex = Regex::new(r"^[a-f0-9]{64}$").unwrap();

                    if !hash_regex.is_match(machine_hash) {
                        let json_error = serde_json::json!({
                            "error": "machine_hash should contain only symbols a-f 0-9 and have length 64",
                        });
                        let json_error = serde_json::to_string(&json_error).unwrap();
                        let response = Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Body::from(json_error))
                            .unwrap();

                        return Ok::<_, Infallible>(response);
                    }

                    if !hash_regex.is_match(lambda_hash) {
                        let json_error = serde_json::json!({
                            "error": "lambda_hash should contain only symbols a-f 0-9 and have length 64",
                        });
                        let json_error = serde_json::to_string(&json_error).unwrap();
                        let response = Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Body::from(json_error))
                            .unwrap();

                        return Ok::<_, Infallible>(response);
                    }

                    let ruleset_header = req.headers().get("X-Ruleset");

                    let signing_requested = std::env::var("BLS_PRIVATE_KEY").is_ok();

                    let mut ruleset_bytes = Vec::new();

                    if signing_requested {
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

                                return Ok::<_, Infallible>(response);
                            }
                        };

                        ruleset_bytes = match hex::decode(ruleset_hex) {
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

                                return Ok::<_, Infallible>(response);
                            }
                        };

                        if ruleset_bytes.len() != 32 {
                            let json_error = serde_json::json!({
                                "error": "Invalid X-Ruleset header: must decode to 32 bytes",
                            });
                            let json_error = serde_json::to_string(&json_error).unwrap();
                            let response = Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(json_error))
                                .unwrap();

                            return Ok::<_, Infallible>(response);
                        }
                    }

                    let payload = hyper::body::to_bytes(req.into_body())
                        .await
                        .unwrap()
                        .to_vec();

                    let mut hasher = Keccak256::new();
                    hasher.update(payload.clone());
                    let payload_keccak = hasher.finalize();

                    let snapshot_dir = std::env::var("SNAPSHOT_DIR").unwrap();

                    let lambda_state_next_path = format!(
                        "{}/{}-{}-{}",
                        snapshot_dir,
                        machine_hash,
                        lambda_hash,
                        hex::encode(payload_keccak)
                    );
                    let machine_snapshot_path = format!("{}/{}", snapshot_dir, machine_hash);
                    let lambda_state_previous_path = format!("{}/{}", snapshot_dir, lambda_hash);

                    let mut outputs_vector = Vec::new();
                    let output_callback = |reason: u16, payload: &[u8]| {
                        let mut result: Result<(u16, Vec<u8>), Error> =
                            Ok((reason, payload.to_vec()));
                        outputs_vector.push(result.as_mut().unwrap().clone());
                        return result;
                    };

                    let mut reports_vector = Vec::new();
                    let report_callback = |reason: u16, payload: &[u8]| {
                        let mut result: Result<(u16, Vec<u8>), Error> =
                            Ok((reason, payload.to_vec()));
                        reports_vector.push(result.as_mut().unwrap().clone());
                        return result;
                    };
                    run_advance(
                        machine_snapshot_path,
                        lambda_state_previous_path.as_str(),
                        lambda_state_next_path.as_str(),
                        payload.to_vec(),
                        HashMap::new(),
                        &mut Box::new(report_callback),
                        &mut Box::new(output_callback),
                        HashMap::new(),
                        false,
                    )
                    .unwrap();

                    let mut file_lambda_state_next =
                        File::open(lambda_state_next_path.as_str()).unwrap();

                    let mut file_lambda_state_next_buffer: [u8; CHUNK_SIZE] = [0; CHUNK_SIZE];

                    let mut hasher = Keccak256::new();

                    loop {
                        let read_bytes_count = file_lambda_state_next
                            .read(&mut file_lambda_state_next_buffer)
                            .unwrap();

                        hasher.update(&file_lambda_state_next_buffer[0..read_bytes_count]);
                        if read_bytes_count < CHUNK_SIZE {
                            break;
                        }
                    }

                    let file_keccak = hasher.finalize();
                    std::fs::rename(
                        lambda_state_next_path.as_str(),
                        format!(
                            "{}/{}-{}",
                            snapshot_dir,
                            machine_hash,
                            hex::encode(file_keccak)
                        ),
                    )
                    .unwrap();

                    let json_response = serde_json::json!({
                       "file_keccak":  hex::encode(&file_keccak),
                       "outputs_callback_vector": outputs_vector,
                       "reports_callback_vector": reports_vector,
                    });

                    #[cfg(feature = "bls_signing")]
                    if signing_requested {
                        let bls_private_key_str =
                            std::env::var("BLS_PRIVATE_KEY").expect("BLS_PRIVATE_KEY not set");
                        let bls_key_pair =
                            BlsKeyPair::new(bls_private_key_str).expect("Invalid BLS private key");

                        let mut buffer = vec![0u8; 12];
                        buffer.extend_from_slice(&ruleset_bytes);

                        let machine_hash_bytes =
                            hex::decode(machine_hash).expect("Invalid machine_hash hex");
                        let lambda_hash_bytes =
                            hex::decode(lambda_hash).expect("Invalid lambda_hash hex");
                        let final_lambda_hash_bytes = file_keccak.to_vec();

                        buffer.extend_from_slice(&machine_hash_bytes);
                        buffer.extend_from_slice(&lambda_hash_bytes);
                        buffer.extend_from_slice(&final_lambda_hash_bytes);

                        let sha256_hash = Sha256::digest(&buffer);

                        let signature = bls_key_pair.sign_message(&sha256_hash);

                        let mut signature_bytes = Vec::new();
                        signature
                            .g1_point()
                            .g1()
                            .serialize_uncompressed(&mut signature_bytes)
                            .unwrap();
                        let signature_hex = hex::encode(&signature_bytes);

                        json_response["signature"] = serde_json::Value::String(signature_hex);
                    }

                    let json_response = serde_json::to_string(&json_response).unwrap();

                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from(json_response))
                        .unwrap();

                    return Ok::<_, Infallible>(response);
                }

                (hyper::Method::POST, ["ensure", cid_str, machine_hash, size_str]) => {
                    let hash_regex = Regex::new(r"^[a-f0-9]{64}$").unwrap();

                    if !hash_regex.is_match(machine_hash) {
                        let json_error = serde_json::json!({
                            "error": "machine_hash should contain only symbols a-f 0-9 and have length 64",
                        });
                        let json_error = serde_json::to_string(&json_error).unwrap();
                        let response = Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Body::from(json_error))
                            .unwrap();

                        return Ok::<_, Infallible>(response);
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
                            let json_response = serde_json::to_string(&json_response).unwrap();

                            let response = Response::builder()
                                .status(StatusCode::OK)
                                .body(Body::from(json_response))
                                .unwrap();

                            return Ok::<_, Infallible>(response);
                        } else {
                            let json_response = serde_json::json!({
                                "state": "ready",
                            });
                            let json_response = serde_json::to_string(&json_response).unwrap();

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
                                let directory_cid = match cid_str.parse::<Cid>() {
                                    Ok(cid) => cid,
                                    Err(_) => {
                                        let _ = std::fs::remove_file(&lock_file_path);

                                        let json_error = serde_json::json!({
                                            "error": "Invalid CID",
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

                                let ipfs_url = std::env::var("IPFS_URL")
                                    .unwrap_or("http://127.0.0.1:5001".to_string());

                                let stat_uri =
                                    format!("{}/api/v0/dag/stat?arg={}", ipfs_url, cid_str);

                                let stat_req = Request::builder()
                                    .method("POST")
                                    .uri(stat_uri)
                                    .body(Body::empty())
                                    .unwrap();

                                let client = Client::new();

                                let stat_res = match client.request(stat_req).await {
                                    Ok(res) => res,
                                    Err(err) => {
                                        let _ = std::fs::remove_file(&lock_file_path);

                                        let json_error = serde_json::json!({
                                            "error": format!("Failed to get DAG stat: {}", err),
                                        });
                                        let json_error =
                                            serde_json::to_string(&json_error).unwrap();
                                        let response = Response::builder()
                                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                                            .body(Body::from(json_error))
                                            .unwrap();

                                        return Ok::<_, Infallible>(response);
                                    }
                                };

                                let stat_body_bytes =
                                    hyper::body::to_bytes(stat_res.into_body()).await.unwrap();

                                let stat_json: serde_json::Value = match serde_json::from_slice(
                                    &stat_body_bytes,
                                ) {
                                    Ok(json) => json,
                                    Err(err) => {
                                        let _ = std::fs::remove_file(&lock_file_path);

                                        let json_error = serde_json::json!({
                                            "error": format!("Failed to parse DAG stat response: {}", err),
                                        });
                                        let json_error =
                                            serde_json::to_string(&json_error).unwrap();
                                        let response = Response::builder()
                                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                                            .body(Body::from(json_error))
                                            .unwrap();

                                        return Ok::<_, Infallible>(response);
                                    }
                                };

                                let actual_size = match stat_json["Size"].as_u64() {
                                    Some(size) => size,
                                    None => {
                                        let _ = std::fs::remove_file(&lock_file_path);

                                        let json_error = serde_json::json!({
                                            "error": "Failed to get Size from DAG stat response",
                                        });
                                        let json_error =
                                            serde_json::to_string(&json_error).unwrap();
                                        let response = Response::builder()
                                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                                            .body(Body::from(json_error))
                                            .unwrap();

                                        return Ok::<_, Infallible>(response);
                                    }
                                };

                                if actual_size != expected_size {
                                    let _ = std::fs::remove_file(&lock_file_path);

                                    let json_error = serde_json::json!({
                                        "error": format!("Size mismatch: expected {}, got {}", expected_size, actual_size),
                                    });
                                    let json_error = serde_json::to_string(&json_error).unwrap();
                                    let response = Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(json_error))
                                        .unwrap();

                                    return Ok::<_, Infallible>(response);
                                }

                                if let Err(err) = dedup_download_directory(
                                    &ipfs_url,
                                    directory_cid,
                                    machine_dir.clone(),
                                )
                                .await
                                {
                                    let _ = std::fs::remove_dir_all(&machine_dir);
                                    let _ = std::fs::remove_file(&lock_file_path);
                                    let json_error = serde_json::json!({
                                        "error": format!("Failed to download directory: {}", err),
                                    });
                                    let json_error = serde_json::to_string(&json_error).unwrap();
                                    let response = Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(Body::from(json_error))
                                        .unwrap();

                                    return Ok::<_, Infallible>(response);
                                }

                                let hash_path = format!("{}/hash", machine_dir);

                                let expected_hash_bytes = match async_std::fs::read(&hash_path)
                                    .await
                                {
                                    Ok(bytes) => bytes,
                                    Err(err) => {
                                        let _ = std::fs::remove_dir_all(&machine_dir);
                                        let _ = std::fs::remove_file(&lock_file_path);
                                        let json_error = serde_json::json!({
                                            "error": format!("Failed to read hash file: {}", err),
                                        });
                                        let json_error =
                                            serde_json::to_string(&json_error).unwrap();
                                        let response = Response::builder()
                                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                                            .body(Body::from(json_error))
                                            .unwrap();

                                        return Ok::<_, Infallible>(response);
                                    }
                                };

                                let machine_hash_bytes = match hex::decode(machine_hash) {
                                    Ok(bytes) => bytes,
                                    Err(_) => {
                                        let _ = std::fs::remove_dir_all(&machine_dir);
                                        let _ = std::fs::remove_file(&lock_file_path);
                                        let json_error = serde_json::json!({
                                            "error": "Invalid machine_hash: must be valid hex",
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

                                if expected_hash_bytes != machine_hash_bytes {
                                    let _ = std::fs::remove_dir_all(&machine_dir);
                                    let _ = std::fs::remove_file(&lock_file_path);
                                    let json_error = serde_json::json!({
                                        "error": "Expected hash from /hash file does not match machine_hash",
                                    });
                                    let json_error = serde_json::to_string(&json_error).unwrap();
                                    let response = Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(Body::from(json_error))
                                        .unwrap();

                                    return Ok::<_, Infallible>(response);
                                }

                                let _ = std::fs::remove_file(&lock_file_path);

                                let json_response = serde_json::json!({
                                    "state": "downloaded",
                                });
                                let json_response = serde_json::to_string(&json_response).unwrap();

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
                                    let json_error = serde_json::to_string(&json_error).unwrap();
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
        }))
    });

    let server = Server::bind(&addr).serve(Box::new(service));
    println!("Server is listening on {}", addr);
    server.await.unwrap();
}

async fn dedup_download_directory(
    ipfs_url: &str,
    directory_cid: Cid,
    out_file_path: String,
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

    std::fs::create_dir_all(&out_file_path)?;

    for val in &first_object.links {
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

                read_single_file_seek(&mut f, &mut out, None).await?;
            }
            Err(err) => {
                return Err(format!("Error downloading file {}: {}", val.name, err).into());
            }
        }
    }

    Ok(())
}
