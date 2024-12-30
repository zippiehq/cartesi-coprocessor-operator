use committable::{Commitment, Committable};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct NamespaceId(u64);

#[derive(Serialize, Deserialize)]
pub struct EspressoTransaction {
    namespace: NamespaceId,
    payload: Vec<u8>,
}

impl Committable for EspressoTransaction {
    fn commit(&self) -> Commitment<Self> {
        committable::RawCommitmentBuilder::new("Transaction")
            .u64_field("namespace", self.namespace.0)
            .var_size_bytes(&self.payload)
            .finalize()
    }
}
