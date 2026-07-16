use crate::{merkle::MerkleTree, tag};
use bitcoin::block;
use hex_fmt::HexFmt;
use std::{fs::File, str::from_utf8};
use std::io::Write;
use reqwest::blocking::get;
use bitcoin::{
    Transaction,
    blockdata::{
        opcodes::all::OP_RETURN,
        script::Instruction,
    }, 
    consensus::encode::deserialize
};
use serde_json::{Value, Number};
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

fn lookup_chain() {
    let url = "https://blockchain.info/rawtx/b82b914e29fb08e65e49156231b68c38c3bcb246f6a7d8ec22477478a9f1b832?format=hex";
    let filepath = "testing/tx.txt";
    let response = get(url).unwrap();
    let content = response.bytes().unwrap();

    let mut downloaded_file = File::create(filepath).unwrap();
    downloaded_file.write_all(&content).unwrap();
}

fn parse_tx_dump() {
    let tx_hex = "02000000000101af4c4c2b0c12159abb3fa3b9f8ac12992f8ac4ccd55805f4b195e903c46d64a40100000000fdffffff0200000000000000004f6a4c4c50474d45524b4c4500012d39e56bf7ee52b351da728a072dd6146450616de1e310d9243cf8428d777081dde1deb4859fb5f483d0251cbe9ebe9908e0591a53511311ee07b134354eac324e22e67f0000000000001600144915dd96aaa0b81fd15d52650bab120bcbd1c51102473044022016097070064785b67fed69af0a198131e14a69c72ccf9e7dd21f034e7732d22602201cf4e403a5783ca9302228cec23b251845c0953bca5be7dfa8046e23cd3a15e6012102047ced3d35c63f8a7c436ae48350711787628eb463bf80492d31888e2fcadb7981940e00";

    let bytes = hex::decode(tx_hex).unwrap();
    let tx: Transaction = deserialize(&bytes).unwrap();

    for (_vout, output) in tx.output.iter().enumerate() {
        let mut instructions = output.script_pubkey.instructions();
        match instructions.next() {
            Some(Ok(Instruction::Op(op))) if op == OP_RETURN => {
                for instruction in instructions {
                    match instruction {
                        Ok(Instruction::PushBytes(data)) => {
                            println!("Payload: {}", HexFmt(data.as_bytes()));
                        }
                        Ok(Instruction::Op(_op)) => {}
                        Err(_) => unimplemented!()
                    }
                }
            }
            _ => {}
        }
    }
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