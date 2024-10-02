use advance_runner::run_advance;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Response, Server, StatusCode};
use regex::Regex;
use sha3::{Digest, Keccak256};
use std::{
    collections::HashMap,
    convert::Infallible,
    fs::File,
    io::{Error, ErrorKind, Read},
    net::SocketAddr,
};
const CHUNK_SIZE: usize = 131072;

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
                    run_advance(
                        machine_snapshot_path,
                        lambda_state_previous_path.as_str(),
                        lambda_state_next_path.as_str(),
                        payload.to_vec(),
                        HashMap::new(),
                        Box::new(report_callback),
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

                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from(hex::encode(file_keccak)))
                        .unwrap();

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
    server.await.unwrap();
}
fn report_callback(reason: u16, payload: &[u8]) -> Result<(u16, Vec<u8>), Error> {
    return Err(Error::from(ErrorKind::Other));
}
