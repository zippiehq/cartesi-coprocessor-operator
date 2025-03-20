use std::{
    fs::File,
    path::Path,
    str::FromStr,
};

use anyhow::{Result, anyhow};
use clap::Parser;

use eigen_client_avsregistry::writer::AvsRegistryChainWriter;
use eigen_client_elcontracts::{
    reader::ELChainReader,
    writer::ELChainWriter,
};
use eigen_common::get_signer;
use eigen_utils::slashing::{
    core::allocationmanager::AllocationManager,
    middleware::{
        servicemanagerbase::ServiceManagerBase,
        registrycoordinator::ISlashingRegistryCoordinatorTypes,
        stakeregistry::IStakeRegistryTypes,
    },
};
use eigen_crypto_bls::BlsKeyPair;
use eigen_logging::{init_logger, get_logger, log_level::LogLevel};

use alloy_primitives::{Address, FixedBytes, aliases::U96};
use alloy_sol_types::SolCall;
use alloy_signer_local::PrivateKeySigner;

#[tokio::main]
async fn main() {
    init_logger(LogLevel::Error);
    let log = get_logger();

    let opts = Options::parse();

    if let Err(err) = set_appointee(&opts).await {
        log.fatal("failed to set appointee: {}", &err.to_string());
    }

    if let Err(err) = create_total_delegated_stake_quorum(&opts).await {
        log.fatal("failed to create total delegated stake quorum: {}", &err.to_string());
    }

    if let Err(err) = register_for_operator_sets(&opts).await {
        log.fatal("failed to register for operator sets: {}", &err.to_string());
    }
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
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EigenlayerDeployment {
    pub addresses: EigenlayerDeploymentAddresses
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
    pub addresses: AvsDeploymentAddresses
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
    pub pauser_registry: Address,
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

async fn set_appointee(opts: &Options) -> Result<()> {
    let log = get_logger();
    
    let el_deployment  = opts.el_deployment()?;
    let avs_deployment = opts.avs_deployment()?;
    let operator_address = opts.operator_address()?;
    let signer = get_signer(&opts.operator_private_key, &opts.el_node_url);
    
    // ServiceManager.setAppointee for AllocationManager.setAvsRegistrar
    let service_manager = ServiceManagerBase::new(
        avs_deployment.addresses.coprocessor_service_manager,
        signer.clone()
    );
    let receipt = service_manager
        .setAppointee(
            operator_address,
            el_deployment.addresses.allocation_manager,
            FixedBytes(AllocationManager::setAVSRegistrarCall::SELECTOR),
        )
        .send()
        .await
        .map_err(|err| anyhow!("failed to send setAvsRegistrar appointee tx: {}", err))?
        .get_receipt()
        .await
        .map_err(|err| anyhow!("failed to get recepit for setAvsRegistrar appointee tx: {}", err))?;
    
    log.info(
        "tx {} successfully included for setAppointee for selector setAvsRegistrar",
        &receipt.transaction_hash.to_string(),
    );

    //  AllocationManager.setAvsRegistrar
    let allocation_manager = AllocationManager::new(
        el_deployment.addresses.allocation_manager,
        signer.clone()
    );
    let receipt = allocation_manager
        .setAVSRegistrar(
            avs_deployment.addresses.coprocessor_service_manager,
            avs_deployment.addresses.registry_coordinator,
        )
        .send()
        .await
        .map_err(|err| anyhow!("failed to send setAvsRegistrar tx: {}", err.to_string()))?
        .get_receipt()
        .await
        .map_err(|err| anyhow!("failed to get receipt for setAvsRegistar tx: {}", err.to_string()))?;

    log.info(
        "tx {} successfully included for setAvsRegistrar tx",
        &receipt.transaction_hash.to_string(),
    );

    // ServiceManager.setAppointee for AllocaitonManager.createOperatorSetsCall
    let receipt = service_manager
        .setAppointee(
            avs_deployment.addresses.registry_coordinator,
            el_deployment.addresses.allocation_manager,
            FixedBytes(AllocationManager::createOperatorSetsCall::SELECTOR),
        )
        .send()
        .await
        .map_err(|err| anyhow!("failed to send createOperatorSets appointee tx: {}", err.to_string()))?
        .get_receipt()
        .await
        .map_err(|err| anyhow!("failed to get receipt for createOperatorSets appointee tx: {}", err.to_string()))?;

    log.info(
        "tx {} successfully included for setAppointee for selector createOperatorSetsCall tx",
        &receipt.transaction_hash.to_string(),
    );

    // ServiceManager.setAppointee for AllocaitonManager.slashOperatorCall
    let receipt = service_manager
        .setAppointee(
            avs_deployment.addresses.slasher,
            el_deployment.addresses.allocation_manager,
            FixedBytes(AllocationManager::slashOperatorCall::SELECTOR),
        )
        .send()
        .await
        .map_err(|err| anyhow!("failed to send slashOperator appointee tx: {}", err.to_string()))?
        .get_receipt()
        .await
        .map_err(|err| anyhow!("failed to get receipt for slashOperator appointee tx: {}", err.to_string()))?;

    log.info(
        "tx {} successfully included for setAppointee for selector slashOperatorCall tx",
        &receipt.transaction_hash.to_string(),
    );
        
    Ok(())
}

async fn create_total_delegated_stake_quorum(opts: &Options) -> Result<()> {
    let avs_deployment = opts.avs_deployment()?;
    
    let operator_set_params = ISlashingRegistryCoordinatorTypes::OperatorSetParam{
        maxOperatorCount: 3,
        kickBIPsOfOperatorStake: 100,
        kickBIPsOfTotalStake: 1000,
    };
    let strategy_params = IStakeRegistryTypes::StrategyParams{
        strategy: avs_deployment.addresses.strategy,
        multiplier: U96::from(1),
    };

    let avs_writer = AvsRegistryChainWriter::build_avs_registry_chain_writer(
        get_logger(),
        opts.el_node_url.clone(),
        opts.operator_private_key.clone(),
        avs_deployment.addresses.registry_coordinator,
        avs_deployment.addresses.operator_state_retriever,
    ).await?;
    let tx_hash = avs_writer.create_total_delegated_stake_quorum(
        operator_set_params,
        U96::from(0),
        vec![strategy_params],
    ).await?;

    get_logger().info("tx {} createTotalDelegatedStakeQuorum successfully included", &tx_hash.to_string());

    Ok(())
}

async fn register_for_operator_sets(opts: &Options) -> Result<()> {
    let el_deployment  = opts.el_deployment()?;
    let avs_deployment = opts.avs_deployment()?;
    let operator_address = opts.operator_address()?;
    let operator_bls_key_pair = opts.operator_bls_key_pair()?;
    
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

    let tx_hash = el_writer.register_for_operator_sets(
        operator_address, 
        avs_deployment.addresses.coprocessor_service_manager,
        vec![0],
        operator_bls_key_pair,
        &opts.operator_socket,
    ).await?;

    get_logger().info("tx {} registerForOperatorSets successfully included", &tx_hash.to_string());
    
    Ok(())
}
