use std::{
    fs::File,
    path::Path,
    str::FromStr,
};

use anyhow::Result;
use clap::Parser;

use alloy_primitives::Address;
use alloy_signer_local::PrivateKeySigner;

use eigen_crypto_bls::BlsKeyPair;

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

    pub fn signer(&self) -> Result<PrivateKeySigner> {
        let signer = PrivateKeySigner::from_str(&self.operator_private_key)?;
        Ok(signer)
    }

    pub fn bls_key_pair(&self) -> Result<BlsKeyPair> {
        let key_pair = BlsKeyPair::new(self.operator_bls_key.to_string())?;
        Ok(key_pair)
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EigenlayerDeployment {
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
    pub L1_sender: Address,
    pub L2_coprocessor: Address,
    pub L2_coprocessor_caller: Address,
    pub bls_apk_registry: Address,
    pub coprocessor: Address,
    pub coprocessor_service_manager: Address,
    pub coprocessor_to_L2: Address,
    pub index_registry: Address,
    pub operator_state_retriever: Address,
    pub pauser_registry: Address,
    pub proxy_admin: Address,
    pub registry_coordinator: Address,
    pub socket_registry: Address,
    pub stake_registry: Address,
    pub strategy: Address,
    pub strategy_token: Address
}
