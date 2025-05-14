use std::{fs::File, path::Path, str::FromStr};

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use url::Url;

use eigen_client_elcontracts::{
    error::ElContractsError, reader::ELChainReader, writer::ELChainWriter,
};
use eigen_crypto_bls::BlsKeyPair;
use eigen_logging::{get_logger, init_logger, log_level::LogLevel};
use eigen_utils::slashing::core::allocationmanager::AllocationManager::AllocationManagerErrors;

use alloy_json_rpc::ErrorPayload;
use alloy_primitives::{Address, TxHash};
use alloy_provider::{PendingTransactionBuilder, PendingTransactionError, ProviderBuilder};
use alloy_rpc_types::eth::TransactionReceipt;
use alloy_signer_local::PrivateKeySigner;

#[tokio::main]
async fn main() {
    init_logger(LogLevel::Info);
    let log = get_logger();

    let opts = Options::parse();

    if let Err(err) = register_for_operator_sets(&opts).await {
        log.error("failed to register for operator sets", &err.to_string());
        std::process::exit(1)
    }

    log.info("operator successfully registered", "")
}

#[derive(Parser, Clone, Debug)]
pub struct Options {
    #[clap(long, env = "EL_DEPLOYMENT_FILE_PATH")]
    pub el_deployment_file_path: String,

    #[clap(long, env = "AVS_DEPLOYMENT_FILE_PATH")]
    pub avs_deployment_file_path: String,

    #[clap(long, env = "OPERATOR_PRIVATE_KEY")]
    pub operator_private_key: String,

    #[clap(long, env = "OPERATOR_BLS_KEY")]
    pub operator_bls_key: String,

    #[clap(long, env = "OPERATOR_SOCKET")]
    pub operator_socket: String,

    #[clap(long, env = "EL_NODE_URL")]
    pub el_node_url: String,

    #[clap(long, default_value_t = 1090000, env = "MAX_GAS")]
    pub max_gas: u64,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EigenlayerDeployment {
    pub addresses: EigenlayerDeploymentAddresses,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EigenlayerDeploymentAddresses {
    pub allocation_manager: Address,
    pub avs_directory: Address,
    pub delegation_manager: Address,
    pub eigen_pod_beacon: Address,
    pub eigen_pod_manager: Address,
    pub pauser_registry: Address,
    pub permission_controller: Address,
    pub proxy_admin: Address,
    pub rewards_coordinator: Address,
    pub strategy_beacon: Address,
    pub strategy_factory: Address,
    pub strategy_manager: Address,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvsDeployment {
    pub addresses: AvsDeploymentAddresses,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvsDeploymentAddresses {
    pub l1_sender: Address,
    pub l2_coprocessor: Address,
    pub l2_coprocessor_caller: Address,
    pub bls_apk_registry: Address,
    pub coprocessor: Address,
    pub coprocessor_service_manager: Address,
    pub coprocessor_to_l2: Address,
    pub index_registry: Address,
    pub operator_state_retriever: Address,
    pub proxy_admin: Address,
    pub registry_coordinator: Address,
    pub socket_registry: Address,
    pub stake_registry: Address,
    pub strategy: Address,
    pub strategy_token: Address,
    pub slasher: Address,
}

impl Options {
    pub fn el_deployment(&self) -> Result<EigenlayerDeployment> {
        let deployment_file = File::open(Path::new(&self.el_deployment_file_path))?;
        let deployment: EigenlayerDeployment = serde_json::from_reader(deployment_file)?;
        Ok(deployment)
    }

    pub fn avs_deployment(&self) -> Result<AvsDeployment> {
        let deployment_file = File::open(Path::new(&self.avs_deployment_file_path))?;
        let deployment: AvsDeployment = serde_json::from_reader(deployment_file)?;
        Ok(deployment)
    }

    pub fn operator_address(&self) -> Result<Address> {
        let signer = PrivateKeySigner::from_str(&self.operator_private_key)?;
        Ok(signer.address())
    }

    pub fn operator_bls_key_pair(&self) -> Result<BlsKeyPair> {
        let key_pair = BlsKeyPair::new(self.operator_bls_key.to_string())?;
        Ok(key_pair)
    }
}

async fn register_for_operator_sets(opts: &Options) -> Result<()> {
    let el_deployment = opts.el_deployment()?;
    let avs_deployment = opts.avs_deployment()?;
    let operator_address = opts.operator_address()?;
    let operator_bls_key_pair = opts.operator_bls_key_pair()?;
    let max_gas = opts.max_gas;

    get_logger().info("registring operator", &operator_address.to_string());

    let el_reader = ELChainReader::new(
        get_logger(),
        Some(el_deployment.addresses.allocation_manager),
        el_deployment.addresses.delegation_manager,
        el_deployment.addresses.rewards_coordinator,
        el_deployment.addresses.avs_directory,
        Some(el_deployment.addresses.permission_controller),
        opts.el_node_url.clone(),
    );

    let el_writer = ELChainWriter::new(
        el_deployment.addresses.strategy_manager,
        el_deployment.addresses.rewards_coordinator,
        Some(el_deployment.addresses.permission_controller),
        Some(el_deployment.addresses.allocation_manager),
        avs_deployment.addresses.registry_coordinator,
        el_reader.clone(),
        opts.el_node_url.clone(),
        opts.operator_private_key.clone(),
    );

    let result = el_writer
        .register_for_operator_sets_with_gas(
            operator_address,
            avs_deployment.addresses.coprocessor_service_manager,
            vec![0],
            operator_bls_key_pair,
            &opts.operator_socket,
            max_gas,
        )
        .await;

    let tx_hash = if let Err(ref err) = result {
        if is_custom_error(&err) {
            let msg = decode_custom_error(&err)
                .map_err(|err| anyhow!("failed to decode custom errror: {}", err))?;
            bail!("{}: {}", err, msg)
        } else {
            bail!("failed to send registerForOperatorSets tx: {}", err)
        }
    } else {
        result.unwrap()
    };

    get_logger().info("tx registerForOperatorSets sent", &tx_hash.to_string());

    let el_node_url =
        Url::parse(&opts.el_node_url).map_err(|err| anyhow!("invalid rpc url: {}", err))?;
    let transaction_receipt = wait_for_pendig_tx(el_node_url, tx_hash).await?;

    if !transaction_receipt.inner.status() {
        return Err(anyhow!(
            "transaction-receipt status {:?}",
            transaction_receipt.inner
        ));
    }

    get_logger().info(
        "tx registerForOperatorSets successfully included",
        &tx_hash.to_string(),
    );

    Ok(())
}

fn is_custom_error(err: &ElContractsError) -> bool {
    err.to_string().contains("custom error")
}

fn decode_custom_error(err: &ElContractsError) -> Result<String> {
    let msg = err.to_string();
    let p1 = msg.find("custom error").expect("not custom error");
    let (_, s) = msg.split_at(p1);
    let (_, s) = s.split_at("custom error".len() + 1);

    let data_end = s.find(",").expect("not custom error");
    let data_hex = &s[0..data_end];

    let payload_json = serde_json::json!({
        "code": 3,
        "message": "execution reverted",
        "data": data_hex
    })
    .to_string();
    let payload: ErrorPayload = serde_json::from_str(&payload_json)?;

    let decoded = payload.as_decoded_interface_error::<AllocationManagerErrors>();
    if decoded.is_none() {
        bail!("not an AllocationManager error")
    }

    let msg = match decoded.unwrap() {
        AllocationManagerErrors::AlreadyMemberOfSet(_) => "AlreadyMemberOfSet",
        AllocationManagerErrors::CurrentlyPaused(_) => "CurrentlyPaused",
        AllocationManagerErrors::Empty(_) => "Empty",
        AllocationManagerErrors::InputAddressZero(_) => "InputAddressZero",
        AllocationManagerErrors::InputArrayLengthMismatch(_) => "InputArrayLengthMismatch",
        AllocationManagerErrors::InsufficientMagnitude(_) => "InsufficientMagnitude",
        AllocationManagerErrors::InvalidAVSRegistrar(_) => "InvalidAVSRegistrar",
        AllocationManagerErrors::InvalidCaller(_) => "InvalidCaller",
        AllocationManagerErrors::InvalidNewPausedStatus(_) => "InvalidNewPausedStatus",
        AllocationManagerErrors::InvalidOperator(_) => "InvalidOperator",
        AllocationManagerErrors::InvalidOperatorSet(_) => "InvalidOperatorSet",
        AllocationManagerErrors::InvalidPermissions(_) => "InvalidPermissions",
        AllocationManagerErrors::InvalidShortString(_) => "InvalidShortString",
        AllocationManagerErrors::InvalidSnapshotOrdering(_) => "InvalidSnapshotOrdering",
        AllocationManagerErrors::InvalidWadToSlash(_) => "InvalidWadToSlash",
        AllocationManagerErrors::ModificationAlreadyPending(_) => "ModificationAlreadyPending",
        AllocationManagerErrors::NonexistentAVSMetadata(_) => "NonexistentAVSMetadata",
        AllocationManagerErrors::NotMemberOfSet(_) => "NotMemberOfSet",
        AllocationManagerErrors::OnlyPauser(_) => "OnlyPauser",
        AllocationManagerErrors::OnlyUnpauser(_) => "OnlyUnpauser",
        AllocationManagerErrors::OperatorNotSlashable(_) => "OperatorNotSlashable",
        AllocationManagerErrors::OutOfBounds(_) => "OutOfBounds",
        AllocationManagerErrors::SameMagnitude(_) => "SameMagnitude",
        AllocationManagerErrors::StrategiesMustBeInAscendingOrder(_) => {
            "StrategiesMustBeInAscendingOrder"
        }
        AllocationManagerErrors::StrategyAlreadyInOperatorSet(_) => "StrategyAlreadyInOperatorSet",
        AllocationManagerErrors::StrategyNotInOperatorSet(_) => "StrategyNotInOperatorSet",
        AllocationManagerErrors::StringTooLong(_) => "StringTooLong",
        AllocationManagerErrors::UninitializedAllocationDelay(_) => "UninitializedAllocationDelay",
    };

    Ok(msg.to_string())
}

pub async fn wait_for_pendig_tx(
    el_node_url: Url,
    tx_hash: TxHash,
) -> Result<TransactionReceipt, PendingTransactionError> {
    let root_provider = ProviderBuilder::new()
        .disable_recommended_fillers()
        .on_http(el_node_url);

    let pending_tx = PendingTransactionBuilder::new(root_provider, tx_hash);
    pending_tx.get_receipt().await
}
