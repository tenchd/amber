use crate::{
    FailureReason, merkle::{MerkleProof, MerkleTree}, tag
};
use hex_fmt::HexFmt;
use bitcoin::{
    Transaction, blockdata::{
        opcodes::all::OP_RETURN,
        script::Instruction,
    }, consensus::encode::deserialize
};
use serde_json::Value;
use std::{io::BufRead, time::Duration};
use text_template::Template;
use std::collections::HashMap;

pub struct TimestampBlockchainDetails {
    pub block_height: usize,
    pub timestamp: i64,
}

fn compute_tag(identifier: &str, num_leaves: u32, root_hash: [u8; 32], explain_hash: [u8; 32]) -> Vec<u8> {

    let tag = tag::create_chain_tag(identifier, num_leaves, root_hash, explain_hash);

    tag
}

fn check_http_status(
    response: reqwest::Response,
) -> Result<reqwest::Response, FailureReason> {
    let status = response.status();

    if status.is_success() {
        Ok(response)
    } else {
        println!("Blockchain explorer returned HTTP status {}.", status);
        Err(FailureReason::UnexpectedBlockchainResponse)
    }
}

async fn verify_tag_async(
    client: &reqwest::Client,
    expected_tag: Vec<u8>,
    tx_hash: [u8; 32],
    verbose: bool,
) -> (Option<TimestampBlockchainDetails>, FailureReason) {
    let tx_hash_string = format!("{}", HexFmt(tx_hash));

    if verbose {
        println!(
            "Looking up transaction with hash {} on Bitcoin blockchain. \
             It should have an OP_RETURN output with the timestamp's tag in the data payload.",
            tx_hash_string
        );
    }

    let json_url = format!("https://blockchain.info/rawtx/{}", tx_hash_string);
    let hex_url = format!(
        "https://blockchain.info/rawtx/{}?format=hex",
        tx_hash_string
    );

    let (json_result, hex_result) = tokio::join!(
        client.get(&json_url).send(),
        client.get(&hex_url).send(),
    );

    let json_response = match json_result {
        Ok(response) => match check_http_status(response) {
            Ok(response) => response,
            Err(reason) => return (None, reason),
        },
        Err(_) => {
            println!("Blockchain explorer website did not respond.");
            return (None, FailureReason::NoBlockchainResponse);
        }
    };

    let hex_response = match hex_result {
        Ok(response) => match check_http_status(response) {
            Ok(response) => response,
            Err(reason) => return (None, reason),
        },
        Err(_) => {
            println!("Blockchain explorer website did not respond.");
            return (None, FailureReason::NoBlockchainResponse);
        }
    };

    let json_string = match json_response.text().await {
        Ok(text) => text,
        Err(_) => {
            println!("Blockchain explorer website did not respond.");
            return (None, FailureReason::NoBlockchainResponse);
        }
    };

    let v: Value = match serde_json::from_str(&json_string){
        Ok(value) => value,
        Err(_) => return (None, FailureReason::UnexpectedBlockchainResponse),
    };

    if v["error"] == "not-found-or-invalid-arg" {
        println!(
            "Blockchain explorer reports tx hash {} does not exist on the chain.",
            HexFmt(tx_hash)
        );
        return (None, FailureReason::TxNotFound);
    }

    let block_height: usize = {match v["block_height"]
        .as_u64() {
            Some(value) => value,
            None => return (None, FailureReason::TxUnconfirmed)
        }}
        .try_into().unwrap();

    let block_url = format!(
        "https://blockchain.info/block-height/{}?format=json",
        block_height
    );

    let block_response = match client.get(&block_url).send().await {
        Ok(response) => match check_http_status(response) {
            Ok(response) => response,
            Err(reason) => return (None, reason),
        },
        Err(_) => {
            println!("Blockchain explorer website did not respond.");
            return (None, FailureReason::NoBlockchainResponse);
        }
    };

    let block_string = match block_response.text().await {
        Ok(text) => text,
        Err(_) => {
            println!("Blockchain explorer website did not respond.");
            return (None, FailureReason::NoBlockchainResponse);
        }
    };

    let b: Value = match serde_json::from_str(&block_string){
        Ok(value) => value,
        Err(_) => return (None, FailureReason::UnexpectedBlockchainResponse),
    };
    let block = &b["blocks"][0];
    let time = block["time"].as_i64().unwrap();

    let content = match hex_response.bytes().await {
        Ok(bytes) => bytes,
        Err(_) => {
            println!("Blockchain explorer website did not respond.");
            return (None, FailureReason::NoBlockchainResponse);
        }
    };

    let string_content = std::str::from_utf8(&content).unwrap();
    let bytes = hex::decode(string_content.trim()).unwrap();
    let tx: Transaction = deserialize(&bytes).unwrap();

    for (_vout, output) in tx.output.iter().enumerate() {
        let mut instructions = output.script_pubkey.instructions();

        match instructions.next() {
            Some(Ok(Instruction::Op(op))) if op == OP_RETURN => {
                for instruction in instructions {
                    match instruction {
                        Ok(Instruction::PushBytes(data)) => {
                            if data.as_bytes() == expected_tag {
                                return (
                                    Some(TimestampBlockchainDetails {
                                        block_height,
                                        timestamp: time,
                                    }),
                                    FailureReason::Success,
                                );
                            }
                        }
                        Ok(Instruction::Op(_op)) => {}
                        Err(_) => return (None, FailureReason::UnexpectedBlockchainResponse),
                    }
                }
            }
            _ => {}
        }
    }

    println!("Tag not found in specified transaction.");
    (None, FailureReason::TagNotFound)
}

#[tokio::main]
pub async fn verify_tree_timestamp(identifier: &str, tree: &MerkleTree, explain_hash: [u8; 32], tx_hash: [u8; 32]) -> (Option<TimestampBlockchainDetails>, FailureReason) {
    //println!("Computing tag based on provided identifier, merkle tree, and explain file.");
    let num_leaves: u32 = tree.num_leaves.try_into().unwrap();
    let root_hash = tree.get_root_hash();
    let expected_tag = compute_tag(identifier, num_leaves, root_hash, explain_hash);
    //println!("The tag should be {}", HexFmt(&expected_tag));

    let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().unwrap();
    verify_tag_async(&client, expected_tag, tx_hash, true).await
}

#[tokio::main]
pub async fn verify_proof_timestamp(proof: &MerkleProof, verbose: bool) -> (bool, FailureReason, Option<i64>,Option<usize>) {
    //println!("Computing tag based on provided identifier, merkle tree, and explain file.");
    let expected_tag = compute_tag(&proof.identifier, proof.num_leaves.try_into().unwrap(), proof.root_hash, proof.explain_hash);
    if verbose {println!("The tag should be {}", HexFmt(&expected_tag));}

    let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().unwrap();
    let (result, mut reason) = verify_tag_async(&client, expected_tag, proof.tx_hash, verbose).await;
    match result {
        Some(details) => {
            let chain_timestamp = details.timestamp;
        let expected_timestamp = proof.utc_timestamp;
            let chain_block_height = details.block_height;
            let expected_block_height = proof.block_height;
            if chain_timestamp == expected_timestamp {
                if chain_block_height != expected_block_height {
                    println!("WARNING: block height {} listed in proof file doesn't match the actual block height {} on the blockchain.", expected_block_height, chain_block_height);
                    reason = FailureReason::BlockHeightMismatchNonFatal;
                }
                return (true, reason, Some(chain_timestamp), Some(chain_block_height));
            }   
            else {
                println!("Timestamp in proof file {} does not match true (blockchain) timestamp {}.", expected_timestamp, chain_timestamp);
                return (true, FailureReason::TimestampMismatchNonFatal, Some(chain_timestamp), Some(chain_block_height));
            }
        }
        _ => {
                println!("Tag (identifier + num_leaves + merkle root hash + explain hash) failed to verify on the blockchain.");
                return (false, reason, None, None)
            }
    }
}

pub fn get_explain_utc_timestamp(explain_filepath: &str) -> (Option<i64>, FailureReason) {
    let file = match std::fs::File::open(explain_filepath) {
        Ok(value) => value,
        Err(_) => return (None, FailureReason::ExplainFileNotFound),
    };
    let mut reader = std::io::BufReader::new(file);
    let mut line = "".to_string();
    match reader.read_line(&mut line) {
        Ok(_) => (),
        Err(_) => return (None, FailureReason::ExplainFileNotParseable(1)),
    }; // ignore first line
    line = "".to_string();
    match reader.read_line(&mut line) {
        Ok(_) => (),
        Err(_) => return (None, FailureReason::ExplainFileNotParseable(2)), // we will parse utc timestamp from second line
    }
    line = line.trim().to_string();
    let utc_timestamp: i64 = match line.parse(){
        Ok(value) => value,
        Err(_) => return (None, FailureReason::ExplainFileNotParseable(2)),
    };
    (Some(utc_timestamp), FailureReason::Success)

}

#[tokio::main]
pub async fn get_current_latest_block() -> (Option<usize>, FailureReason) {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().unwrap();

    let response_result = client
        .post("https://api.blockchain.info/explorer-gateway-kt/btc/blocks")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&serde_json::json!({ "limit": 1 }))
        .send()
        .await;

    if response_result.is_err() {
        println!("Blockchain explorer website did not respond.");
        return (None, FailureReason::NoBlockchainResponse)
    }
    let response = response_result.unwrap();
    let json_string = response.text().await.unwrap();
    let v: Value = serde_json::from_str(&json_string).unwrap();
    let block_height: usize = v["currentHeight"].as_u64().unwrap().try_into().unwrap();

    (Some(block_height), FailureReason::Success)

}

// returns an estimate of the satoshi/vbyte fee required to get mined in the next block.
pub fn get_fee_estimate() -> (Option<f64>, FailureReason) {
    let request_url = "https://mempool.space/api/v1/fees/precise";

    let fee_response = match reqwest::blocking::get(request_url) {
        Ok(response) => response,
        Err(_) => {
            println!("Blockchain explorer website did not respond.");
            return (None, FailureReason::NoBlockchainResponse);
        }
    };

    let fee_string = fee_response.text().unwrap();
    let v: serde_json::Value = serde_json::from_str(&fee_string).unwrap();
    //let fields = vec!["fastestFee", "halfHourFee", "hourFee", "economyFee", "minimumFee"];
    let recommended_fast_fee = v["fastestFee"].as_f64().unwrap();
    let safe_fee = recommended_fast_fee * 1.25;
    (Some(safe_fee), FailureReason::Success)
}

pub fn generate_op_return_script(receiving_address: &str, balance: f64, tag: &str) -> (Option<String>, Option<f64>, FailureReason) {
    let script_template_str = "${receiving_address},${change}\nscript(OP_RETURN ${tag}), 0";
    let script_template = Template::from(script_template_str);
    // fee ratio is in satoshis/vbyte. message will have 198 vbytes. convert to mBTC
    let (fee_estimate_result, reason) = get_fee_estimate();
    let fee_rate = match fee_estimate_result {
        Some(value) => value,
        None => return (None, None, reason),
    };
    let fee = fee_rate * 229.0 * 0.00001;
    let mut change= balance - fee;
    let round_factor = 100000.0;
    change = (change * round_factor).round()/ round_factor;
    if change <= 0.0 {
        return (None, Some(fee), FailureReason::BalanceTooLow)
    }
    let mut values: HashMap<&str, &str> = HashMap::new();
    values.insert("receiving_address", receiving_address);
    let change_str= &format!("{}", change);
    values.insert("change", change_str);
    values.insert("tag", tag);
    let script = script_template.try_fill_in(&values);
    (Some(script.unwrap().to_string()), Some(fee), FailureReason::Success)
}

pub fn tag_valid(tag: &str) -> bool {
    // expect 76 bytes, which is 152 characters in hex
    if tag.len() != 152 {
        return false
    }

    match hex::decode(tag) {
        Ok(_) => return true,
        Err(_) => return false,
    }
}

pub fn check_confirmations(tx_hash_string: &str) -> (Option<usize>, FailureReason) {
    let json_url = format!("https://blockchain.info/rawtx/{}", tx_hash_string);
    let json_result = reqwest::blocking::get(json_url);
    let json_response = match json_result {
        Ok(response) => response,
        Err(_) => {
            println!("Blockchain explorer website did not respond.");
            return (None, FailureReason::NoBlockchainResponse);
        }
    };

    let json_string = match json_response.text() {
        Ok(text) => text,
        Err(_) => {
            println!("Blockchain explorer website did not respond.");
            return (None, FailureReason::NoBlockchainResponse);
        }
    };

    let v: Value = serde_json::from_str(&json_string).unwrap();

    if v["error"] == "not-found-or-invalid-arg" {
        println!(
            "Blockchain explorer reports tx hash {} does not exist on the chain.",
            tx_hash_string
        );
        return (None, FailureReason::TxNotFound);
    }

    let block_height: i64 = match v.get("block_height") {
        None => return (None, FailureReason::NoBlockchainResponse),
        Some(value) => {
            // if block height is null, that means the transaction has 0 confirmations so far.
            if *value == Value::Null {
                return (Some(0), FailureReason::Success)
            }
            value.as_u64().unwrap()
            .try_into().unwrap()
        },
    };

    let (current_height, reason) = get_current_latest_block();
    if current_height.is_none() {
        return (None, reason)
    }
    let current_height: i64 = current_height.unwrap().try_into().unwrap();

    let confirmations = current_height - block_height + 1;
    // edge case handler, in case current height and block height results are out of sync. avoids usize underflow error.
    if confirmations < 0 {
        return (Some(0), FailureReason::Success);
    }
    let confirmations: usize = confirmations.try_into().unwrap();
    return (Some(confirmations), FailureReason::Success)
}
