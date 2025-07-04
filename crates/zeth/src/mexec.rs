use risc0_zkvm::{
    ApiClient, ExecutorEnv,
    Asset, AssetRequest,
    CoprocessorCallback,
    ProveKeccakRequest, ProveZkrRequest,
    sha::{Digest, Digestible},
};
use zeth_preflight::Witness;

use anyhow;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use redis::{Commands};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeccakRequestObject {
    pub claim_digest: [u8; 32],

    pub po2: usize,

    pub control_root: [u8; 32],
    
    // KeccakState in risc0
    pub input: Vec<[u64; 25]>,
}

struct Coprocessor {
    // <claim_digest, blob>
    pub keccak_requests: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Coprocessor {
    pub fn new() -> Self {
        Self {
            keccak_requests: Vec::new(),
        }
    }
}

impl CoprocessorCallback for Coprocessor {
    fn prove_zkr(&mut self, zkr_request: ProveZkrRequest) -> anyhow::Result<()> {
        log::warn!("Zkr request spotted: {:?}", zkr_request.claim_digest);        
        Ok(())
    }

    fn prove_keccak(&mut self, keccak_request: ProveKeccakRequest) -> anyhow::Result<()> {
        // log::info!(
        //     "keccak request: claim: `{:?}`, po2: `{:?}`, control_root: `{:?}`, on: `{}`",
        //     keccak_request.claim_digest,
        //     keccak_request.po2,
        //     keccak_request.control_root,
        //     Local::now().time()
        // );
        let keccak_obj = KeccakRequestObject {
            claim_digest: keccak_request.claim_digest.into(),
            po2: keccak_request.po2,
            control_root: keccak_request.control_root.into(),
            input: keccak_request.input
        };
        let blob = bincode::serialize(&keccak_obj)?;
        self.keccak_requests.push((keccak_request.claim_digest.as_bytes().into(), blob));
        Ok(())
    }
}
pub async fn execute(
    elf: Vec<u8>,
    witness: & Witness
) -> anyhow::Result<Vec<u8>> {
    let client = redis::Client::open("redis://127.0.0.1:6379/")?;
    let mut con = client.get_connection()?;
    // stream cleanup
    let _: () = redis::cmd("DEL")
        .arg("zeth-segment-stream")
        .execute(&mut con);
    let _: () = redis::cmd("DEL")
        .arg("zeth-keccak-stream")
        .execute(&mut con);
    
    let coprocessor = Rc::new(RefCell::new(Coprocessor::new()));

    let exec_env = ExecutorEnv::builder()
        .write_frame(&witness.encoded_rkyv_input)
        .write_frame(&witness.encoded_chain_input)
        .segment_limit_po2(21)
        .coprocessor_callback_ref(coprocessor.clone())
        .build()?;
    let r0_client = ApiClient::from_env()?;

    let mut seg_id = 0usize;
    let session_info = r0_client.execute(
        &exec_env,
        Asset::Inline(elf.into()),
        AssetRequest::Inline,
        |_segment_info, asset| -> anyhow::Result<()> {
            // write to redis
            let _: () = redis::cmd("XADD")
                .arg("zeth-segment-stream")
                .arg("*")
                .arg(&[(seg_id.to_string(), asset.as_bytes()?.as_ref())])
                .query(&mut con)?;
            seg_id += 1;
            Ok(())
        },
    )?;    
    log::info!("Total segments: {seg_id}");
    // notify segmentation is over
    let _: () = redis::cmd("XADD")
        .arg("zeth-segment-stream")
        .arg("*")
        .arg(&[("<done>", "")])
        .query(&mut con)?;        
    // keccak stream
    if !coprocessor.borrow().keccak_requests.is_empty() {
        let _: () = redis::cmd("XADD")
            .arg("zeth-keccak-stream")
            .arg("*")
            .arg(coprocessor.borrow().keccak_requests.as_slice())
            .query(&mut con)?;
    }
    // notify segmentation is over
    let _: () = redis::cmd("XADD")
        .arg("zeth-keccak-stream")
        .arg("*")
        .arg(&[("<done>", "")])
        .query(&mut con)?; 
    log::info!("Total assumptions: {}",
        coprocessor.borrow().keccak_requests.len()
    );
    log::info!("claim: {:#?}", session_info.receipt_claim);
    Ok(session_info.journal.bytes)
}
