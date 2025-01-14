use async_std::task;
use hyper::body::to_bytes;
use hyper::{Body, Client, Request};
use rand::Rng;
#[async_std::main]
async fn main() {
    let mut rng = rand::thread_rng();
    let handles: Vec<_> = (0..1000)
        .map(|i| {
            task::spawn({
                let payload: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
                async move {
                    classic_request_test(payload).await;
                }
            })
        })
        .collect();

    for handle in handles {
        handle.await;
    }
}

async fn classic_request_test(payload: Vec<u8>) {
    let classic_http_request = Request::builder()
        .method("POST")
        .uri(format!(
            "{}/classic/{}",
            std::env::var("OPERATOR_ADDRESS").unwrap(),
            std::env::var("MACHINE_HASH").unwrap()
        ))
        .header("X-Ruleset", generate_random_ruleset())
        .header("X-Max-Ops", 10)
        .body(Body::from(payload))
        .unwrap();
    let http_client = Client::new();

    match http_client.request(classic_http_request).await {
        Ok(classic_http_response) => {
            let response = serde_json::from_slice::<serde_json::Value>(
                &to_bytes(classic_http_response.into_body())
                    .await
                    .unwrap()
                    .to_vec()
            )
            .unwrap();
            println!(
                "outputs_callback_vector : {:?} ; reports_callback_vector : {:?}",
                response.get("outputs_callback_vector").unwrap().as_array().unwrap(),
                response.get("reports_callback_vector").unwrap().as_array().unwrap()

            );
        }
        Err(e) => {
            println!("Error querying classic request {:?}", e);
        }
    }
    println!()
}
fn generate_random_ruleset() -> String {
    let byte_length = 20;
    let mut rng = rand::thread_rng();
    let random_bytes: Vec<u8> = (0..byte_length).map(|_| rng.gen()).collect();
    hex::encode(random_bytes)
}
