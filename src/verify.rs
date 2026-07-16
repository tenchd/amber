use crate::{merkle::MerkleTree, tag};
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
use chrono::{DateTime, NaiveDateTime, Utc};

fn compute_tag(identifier: &str, tree_filename: &str, explain_filepath: &str) -> Vec<u8> {
    println!("reading merkle tree from file.");
    let unfossilized: MerkleTree = MerkleTree::new_from_fossilized_tree(tree_filename);
    println!("Merkle tree has root hash: {}... and contains {} leaves", HexFmt(&unfossilized.get_root_hash()[..4]), unfossilized.num_leaves);
    unfossilized.verify_tree();
    println!("Merkle tree is valid.");

    let num_leaves = unfossilized.num_leaves.try_into().unwrap();
    let root_hash = unfossilized.get_root_hash();
    let tag = tag::create_chain_tag(identifier, num_leaves, root_hash, explain_filepath);
    //let opcodes = "6a4c4c"; //hex of opcodes used to write to bitcoin blockchain via OP_RETURN
    //println!("Blockchain message should be\n{}", HexFmt(&tag));
    tag
}

// need to get later: tx hash. right now i'm cheating and hard coding it.
// also need to read off date and time and block height from tx.
pub fn verify_timestamp(identifier: &str, tree_filename: &str, explain_filepath: &str) -> bool {
    println!("Computing tag based on provided identifier, merkle tree, and explain file.");
    let expected_tag = compute_tag(identifier, tree_filename, explain_filepath);
    println!("The tag should be {}", HexFmt(&expected_tag));
    let cheat_tx_hash = "b82b914e29fb08e65e49156231b68c38c3bcb246f6a7d8ec22477478a9f1b832";

    println!("Looking up transaction with hash {} on Bitcoin blockchain. It should have an OP_RETURN output with the tag in the data payload.", cheat_tx_hash);

    let json_url = format!("https://blockchain.info/rawtx/{}", cheat_tx_hash);
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

    let datetime: DateTime<Utc> = DateTime::from_utc(NaiveDateTime::from_timestamp(time, 0), Utc);

    let hex_url = format!("https://blockchain.info/rawtx/{}?format=hex", cheat_tx_hash);
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