use crate::{
    FailureReason::{self, BlockHeightMismatchNonFatal, NoBlockchainResponse, TimestampMismatchNonFatal}, merkle::{MerkleProof, MerkleTree}, tag
};
use hex_fmt::HexFmt;
use std::str::from_utf8;
use reqwest::blocking::get;
use bitcoin::{
    Transaction,
    blockdata::{
        opcodes::all::OP_RETURN,
        script::Instruction,
    }, 
    consensus::encode::deserialize
};
use serde_json::Value;
use std::io::BufRead;

pub struct TimestampBlockchainDetails {
    pub block_height: usize,
    pub timestamp: i64,
}

fn compute_tag(identifier: &str, num_leaves: u32, root_hash: [u8; 32], explain_hash: [u8; 32]) -> Vec<u8> {

    let tag = tag::create_chain_tag(identifier, num_leaves, root_hash, explain_hash);

    tag
}

fn verify_tag(expected_tag: Vec<u8>, tx_hash: [u8; 32], verbose: bool) -> (Option<TimestampBlockchainDetails>, FailureReason) {
    let tx_hash_string = format!("{}", HexFmt(tx_hash));

    if verbose {println!("Looking up transaction with hash {} on Bitcoin blockchain. It should have an OP_RETURN output with the timestamp's tag in the data payload.", tx_hash_string);}

    let json_url = format!("https://blockchain.info/rawtx/{}", tx_hash_string);
    let json_response; 
    let json_get_response = get(json_url);
    match json_get_response {
        Ok(value) => json_response = value,
        Err(_error) => return (None, FailureReason::NoBlockchainResponse),
    }    
    let json_string = json_response.text().unwrap();
    let v: Value = serde_json::from_str(&json_string).unwrap();
    if v["error"] == "not-found-or-invalid-arg" {
        return (None, FailureReason::TxNotFound)
    }
    let block_height: usize = v["block_height"].as_u64().unwrap().try_into().unwrap();

    let block_url = format!("https://blockchain.info/block-height/{}?format=json", block_height);
    let block_response;
    let block_get_response = get(block_url);
    match block_get_response {
        Ok(value) => block_response = value,
        Err(_error) => return (None, FailureReason::NoBlockchainResponse),
    }
    let block_string = block_response.text().unwrap();
    let b: Value = serde_json::from_str(&block_string).unwrap();
    let block = &b["blocks"][0];
    let time = block["time"].as_i64().unwrap();

    //let datetime: DateTime<Utc> = DateTime::from_naive_utc_and_offset(DateTime::from_timestamp(time, 0).unwrap().naive_utc(), Utc);

    let hex_url = format!("https://blockchain.info/rawtx/{}?format=hex", tx_hash_string);
    let response;
    let get_response= get(hex_url);
    match get_response {
        Ok(value) => response = value,
        Err(_error) => return (None, FailureReason::NoBlockchainResponse),
    }
    let content = response.bytes().unwrap();
    let string_content: String = from_utf8(&content).unwrap().to_string();
    let bytes = hex::decode(string_content).unwrap();
    let tx: Transaction = deserialize(&bytes).unwrap();


    for (_vout, output) in tx.output.iter().enumerate() {
        let mut instructions = output.script_pubkey.instructions();
        match instructions.next() {
            Some(Ok(Instruction::Op(op))) if op == OP_RETURN => {
                for instruction in instructions {
                    match instruction {
                        Ok(Instruction::PushBytes(data)) => {
                            //println!("Payload: {}", HexFmt(data.?format=hexas_bytes()));
                            if data.as_bytes() == expected_tag {
                                //println!("Success! The transaction was found in block {} and contains the tag in its OP_RETURN data payload.", block_height);
                                //println!("You have verified that the provided timestamp was written to the Bitcoin blockchain at date/time {}", datetime);
                                //println!("This block height and date/time should roughly match those in explain.txt.");
                                return (Some(TimestampBlockchainDetails{block_height: block_height, timestamp: time}), FailureReason::Success);
                            }
                        }
                        Ok(Instruction::Op(_op)) => {}
                        Err(_) => unimplemented!()
                    }
                }
            }
            _ => {}
        }
    }

    (None, FailureReason::TagNotFound)
} 

pub fn verify_tree_timestamp(identifier: &str, tree: &MerkleTree, explain_hash: [u8; 32], tx_hash: [u8; 32]) -> (Option<TimestampBlockchainDetails>, FailureReason) {
    //println!("Computing tag based on provided identifier, merkle tree, and explain file.");
    let num_leaves: u32 = tree.num_leaves.try_into().unwrap();
    let root_hash = tree.get_root_hash();
    let expected_tag = compute_tag(identifier, num_leaves, root_hash, explain_hash);
    //println!("The tag should be {}", HexFmt(&expected_tag));

    verify_tag(expected_tag, tx_hash, true)
}

pub fn verify_proof_timestamp(proof: &MerkleProof, verbose: bool) -> (bool, FailureReason) {
    //println!("Computing tag based on provided identifier, merkle tree, and explain file.");
    let expected_tag = compute_tag(&proof.identifier, proof.num_leaves.try_into().unwrap(), proof.root_hash, proof.explain_hash);
    if verbose {println!("The tag should be {}", HexFmt(&expected_tag));}

    let (result, mut reason) = verify_tag(expected_tag, proof.tx_hash, verbose);
    match result {
        Some(details) => {
            let chain_timestamp = details.timestamp;
            let expected_timestamp = proof.utc_timestamp;
            if chain_timestamp == expected_timestamp {
                let chain_block_height = details.block_height;
                let expected_block_height = proof.block_height;
                if chain_block_height != expected_block_height {
                    println!("WARNING: block height {} listed in proof file doesn't match the actual block height {} on the blockchain.", expected_block_height, chain_block_height);
                    reason = BlockHeightMismatchNonFatal;
                }
                return (true, reason);
            }   
            else {
                println!("Timestamp in proof file {} does not match true (blockchain) timestamp {}.", expected_timestamp, chain_timestamp);
                return (true, TimestampMismatchNonFatal);
            }
        }
        _ => {
                println!("Tag (identifier + num_leaves + merkle root hash + explain hash) failed to verify on the blockchain.");
                return (false, reason)
            }
    }
}

pub fn get_explain_utc_timestamp(explain_filepath: &str) -> i64 {
    let file = std::fs::File::open(explain_filepath).unwrap();
    let mut reader = std::io::BufReader::new(file);
    let mut line = "".to_string();
    reader.read_line(&mut line).unwrap(); // ignore first line
    line = "".to_string();
    reader.read_line(&mut line).unwrap(); // we will parse utc timestamp from second line
    line.pop();
    let uct_timestamp: i64 = line.parse().unwrap();
    uct_timestamp

}

#[tokio::main]
pub async fn get_current_latest_block() -> (Option<usize>, FailureReason) {
    let client = reqwest::Client::new();

    let response_result = client
        .post("https://api.blockchain.info/explorer-gateway-kt/btc/blocks")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&serde_json::json!({ "limit": 1 }))
        .send()
        .await;

    if response_result.is_err() {
        return (None, NoBlockchainResponse)
    }
    let response = response_result.unwrap();
    let json_string = response.text().await.unwrap();
    let v: Value = serde_json::from_str(&json_string).unwrap();
    let block_height: usize = v["currentHeight"].as_u64().unwrap().try_into().unwrap();

    (Some(block_height), FailureReason::Success)

}