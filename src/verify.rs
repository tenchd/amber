use crate::{
    merkle::{MerkleTree, MerkleProof},
    tag
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
use chrono::{DateTime, Utc};

fn compute_tag(identifier: &str, num_leaves: u32, root_hash: [u8; 32], explain_hash: [u8; 32]) -> Vec<u8> {

    let tag = tag::create_chain_tag(identifier, num_leaves, root_hash, explain_hash);

    tag
}

fn verify_tag(expected_tag: Vec<u8>, tx_hash: [u8; 32]) -> bool {
    let tx_hash_string = format!("{}", HexFmt(tx_hash));

    println!("Looking up transaction with hash {} on Bitcoin blockchain. It should have an OP_RETURN output with the tag in the data payload.", tx_hash_string);

    let json_url = format!("https://blockchain.info/rawtx/{}", tx_hash_string);
    let json_response = get(json_url).unwrap();
    let json_string = json_response.text().unwrap();
    let v: Value = serde_json::from_str(&json_string).unwrap();
    let block_height = v["block_height"].as_u64().unwrap();

    let block_url = format!("https://blockchain.info/block-height/{}?format=json", block_height);
    let block_response = get(block_url).unwrap();
    let block_string = block_response.text().unwrap();
    let b: Value = serde_json::from_str(&block_string).unwrap();
    let block = &b["blocks"][0];
    let time = block["time"].as_i64().unwrap();

    //let datetime: DateTime<Utc> = DateTime::from_utc(NaiveDateTime::from_timestamp(time, 0), Utc);
    let datetime: DateTime<Utc> = DateTime::from_naive_utc_and_offset(DateTime::from_timestamp(time, 0).unwrap().naive_utc(), Utc);

    let hex_url = format!("https://blockchain.info/rawtx/{}?format=hex", tx_hash_string);
    let response = get(hex_url).unwrap();
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
                                println!("Success! The transaction was found in block {} and contains the tag in its OP_RETURN data payload.", block_height);
                                println!("You have verified that the provided timestamp was written to the Bitcoin blockchain at date/time {}", datetime);
                                println!("This block height and date/time should roughly match those in explain.txt.");
                                return true;
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

    false
} 

pub fn verify_tree_timestamp(identifier: &str, tree: &MerkleTree, explain_hash: [u8; 32], tx_hash: [u8; 32]) -> bool {
    println!("Computing tag based on provided identifier, merkle tree, and explain file.");
    let num_leaves: u32 = tree.num_leaves.try_into().unwrap();
    let root_hash = tree.get_root_hash();
    let expected_tag = compute_tag(identifier, num_leaves, root_hash, explain_hash);
    println!("The tag should be {}", HexFmt(&expected_tag));

    verify_tag(expected_tag, tx_hash)
}

pub fn verify_proof_timestamp(proof: &MerkleProof) -> bool {
    println!("Computing tag based on provided identifier, merkle tree, and explain file.");
    let expected_tag = compute_tag(&proof.identifier, proof.num_leaves.try_into().unwrap(), proof.root_hash, proof.explain_hash);
    println!("The tag should be {}", HexFmt(&expected_tag));

    verify_tag(expected_tag, proof.tx_hash)
}