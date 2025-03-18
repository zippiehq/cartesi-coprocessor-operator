use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_signer_local::PrivateKeySigner;
use clap::Parser;
use eigen_client_avsregistry::writer::AvsRegistryChainWriter;
use eigen_client_elcontracts::{
    reader::ELChainReader,
    writer::{ELChainWriter, Operator},
};
use eigen_crypto_bls::BlsKeyPair;
use eigen_logging::get_test_logger;
use eigen_testing_utils::transaction::wait_transaction;
//use eigen_utils::erc20::ERC20;
use eigen_common::get_signer;
use eigen_utils::slashing::{
    core::strategymanager::StrategyManager,
    middleware::ierc20::IERC20::{self, IERC20Instance},
};
use setup_operator::Options;
use std::{
    fs::File,
    path::Path,
    process::exit,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

#[tokio::main]
async fn main() {
    let opts = Options::parse();
    
    let el_deployment = match opts.el_deployment() {
        Ok(deployment) => deployment,
        Err(err) => {
            eprintln!("invalid eigenlayer deployment: {}", err);
            exit(1)
        }
    };

    let avs_deployment = match opts.avs_deployment() {
        Ok(deployment) => deployment,
        Err(err) => {
            eprintln!("invalid avs deployment: {}", err);
            exit(1)
        }
    };

    let signer = match opts.signer() {
        Ok(signer) => signer,
        Err(err) => {
            eprintln!("invalid operator private key: {}", err);
            exit(1)
        }
    };

    let bls_key_pair = match opts.bls_key_pair() {
        Ok(key_pair) => key_pair,
        Err(err) => {
            eprintln!("invalid operator bls key: {}", err);
            exit(1)
        }
    };

    // !!!
    /*
    let signer = PrivateKeySigner::from_str(&opt.operator_private_key).unwrap();

    let deployment_parameters_devnet =
        File::open(Path::new(&opt.chain_writer_reader_addresses)).unwrap();

    let json: serde_json::Value = serde_json::from_reader(deployment_parameters_devnet).unwrap();

    let delegation_manager_address = 
        Address::parse_checksummed(json.get("delegationManager").unwrap().as_str().unwrap(), None)
            .unwrap();

    let avs_directory_address =
        Address::parse_checksummed(json.get("avsDirectory").unwrap().as_str().unwrap(), None)
            .unwrap();

    let allocation_manager_address =
        Address::parse_checksummed(json.get("allocationManager").unwrap().as_str().unwrap(), None)
            .unwrap();
    
    let strategy_manager_address =
        Address::parse_checksummed(json.get("strategyManager").unwrap().as_str().unwrap(), None)
            .unwrap();

    let rewards_coordinator_address =
        Address::parse_checksummed(json.get("rewardsCoordinator").unwrap().as_str().unwrap(), None)
            .unwrap();

    let permission_controller_address =
        Address::parse_checksummed(json.get("permissionController").unwrap().as_str().unwrap(), None)
            .unwrap();
    */

    let el_reader = ELChainReader::new(
        get_test_logger(),
        Some(el_deployment.allocation_manager),
        el_deployment.delegation_manager,
        el_deployment.rewards_coordinator,
        el_deployment.avs_directory,
        Some(el_deployment.permission_controller),
        opts.el_node_url.to_owned(),
    );

    let el_writer = ELChainWriter::new(
        el_deployment.strategy_manager,
        el_deployment.rewards_coordinator,
        Some(el_deployment.permission_controller),
        Some(el_deployment.allocation_manager),
        avs_deployment.registry_coordinator,
        el_reader.clone(),
        opts.el_node_url.to_string(),
        opts.operator_private_key.to_string(),
    );

    let operator_details = Operator {
        address: signer.address(),
        delegation_approver_address: signer.address(),
        metadata_url: "eigensdk-rs".to_string(),
        allocation_delay: None,
        _deprecated_earnings_receiver_address: Some(signer.address()),
        staker_opt_out_window_blocks: Some(3),
    };

    // !!!
    /* let _ = el_chain_writer
        .register_as_operator(operator_details)
        .await
        .unwrap();
    */

    // !!!
    /* 
    let provider = get_signer(
        &opt.operator_private_key.to_string(),
        &opt.el_node_url.to_string(),
    );

    let coprocessor_deployment_output_devnet =
        File::open(Path::new(&opt.avs_registry_writer_addresses)).unwrap();

    let json: serde_json::Value =
        serde_json::from_reader(coprocessor_deployment_output_devnet).unwrap();

    let registry_coordinator = Address::parse_checksummed(
        json.get("addresses")
            .unwrap()
            .get("registryCoordinator")
            .unwrap()
            .as_str()
            .unwrap(),
        None,
    )
    .unwrap();

    let operator_state_retriever = Address::parse_checksummed(
        json.get("addresses")
            .unwrap()
            .get("operatorStateRetriever")
            .unwrap()
            .as_str()
            .unwrap(),
        None,
    )
    .unwrap();
    */

    let avs_writer = AvsRegistryChainWriter::build_avs_registry_chain_writer(
        get_test_logger(),
        opts.el_node_url.to_string(),
        opts.operator_private_key,
        avs_deployment.registry_coordinator,
        avs_deployment.operator_state_retriever,
    ).await.unwrap();

    // !!!
    /*
    let bls_key_pair = BlsKeyPair::new(opt.operator_bls_key.to_string()).unwrap();
    let salt: FixedBytes<32> = FixedBytes::from([0x03; 32]);
    let now = SystemTime::now();
    let seconds_since_epoch = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let expiry = U256::from(seconds_since_epoch) + U256::from(10000);
    let quorum_numbers = Bytes::from_str("0x00").unwrap();
    
    let tx_hash = avs_writer
        .register_operator_in_quorum_with_avs_registry_coordinator(
            bls_key_pair,
            salt,
            expiry,
            quorum_numbers,
            opts.operator_socket,
        )
        .await
        .unwrap();
    wait_transaction(&opts.el_node_url, tx_hash).await.unwrap();
    println!("setup_operator finished");
    */
}


