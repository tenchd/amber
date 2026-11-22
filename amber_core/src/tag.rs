use std::fs::File;
use std::io::Write;
use hex_fmt::HexFmt;
use text_template::Template;
use std::collections::HashMap;

use crate::{AMBER_VERSION, AMBER_VERSION_DATE, CORPUS_DESCRIPTION, CORPUS_MOTIVATION, EXPLAIN_TEMPLATE, FailureReason, USER_DESCRIPTION};

// Create the identifier, num_leaves, and root hash part of the tag that will be written to the blockchain.
pub fn create_chain_tag_prefix(identifier: &str, num_merkle_leaves: u32, merkle_root_hash: [u8; 32]) -> Vec<u8> {
    assert!(identifier.is_ascii(), "Identifier must be ascii characters only.");
    assert!(identifier.len() == 8, "Identifier must have exactly 8 characters. You supplied {}", identifier.len());

    let num_merkle_leaves_as_bytes: [u8; 4] = num_merkle_leaves.to_be_bytes();
    let result = [identifier.as_bytes(), &num_merkle_leaves_as_bytes, &merkle_root_hash].concat();
    result
}

// Creates the 76-byte tag that will be written to the blockchain.
pub fn create_chain_tag(identifier: &str, num_merkle_leaves: u32, merkle_root_hash: [u8; 32], explainer_hash: [u8; 32]) -> Vec<u8> {
    let prefix = create_chain_tag_prefix(identifier, num_merkle_leaves, merkle_root_hash);

    //let explainer_hash = double_hash_from_file(explainer_file_path);

    let result = [prefix, explainer_hash.to_vec()].concat();
    assert!(result.len() == 76, "Result should have 76 bytes. You had {}", result.len());
    //println!("Wrote identifier {},\n# merkle leaves {},\nmerkle root hash {},\nand explainer hash {}\nto bytes.\n
    //Result: {}\n", identifier, num_merkle_leaves, HexFmt(merkle_root_hash), HexFmt(explainer_hash), HexFmt(&result));
    result
}

// Inserts relevant details about the merkle tree, target block, day & time, etc. into the explanatory document and writes the document as a txt file.
pub fn write_document(output_filename: &str, corpus_name: &str, utc: chrono::DateTime<chrono::Utc>, date: &str, time: &str, locktime: usize, identifier: &str, num_merkle_leaves: u32, merkle_root_hash: [u8; 32], corpus_desc: Option<String>, corpus_motiv: Option<String>, user_desc: Option<String>) -> FailureReason {
    let template = Template::from(EXPLAIN_TEMPLATE);

    let mut values: HashMap<&str, &str> = HashMap::new();
    let utc_timestamp = &utc.timestamp().to_string();
    values.insert("utc_timestamp", utc_timestamp);
    values.insert("date",date);
    values.insert("time",time);
    let binding = locktime.to_string();
    let locktime = (&binding).as_str();
    values.insert("locktime",locktime);
    values.insert("identifier",identifier);
    let hex_identifier_string = format!("{}", HexFmt(identifier.as_bytes()));
    values.insert("identifier_hex", hex_identifier_string.as_str());
    let num_merkle_leaves_string = num_merkle_leaves.to_string();
    values.insert("num_merkle_leaves",&num_merkle_leaves_string.as_str());
    let hex_leaves_string = format!("{}", HexFmt(num_merkle_leaves.to_be_bytes()));
    values.insert("num_merkle_leaves_hex",&hex_leaves_string.as_str());
    let root_hash_hex_string = format!("{}", HexFmt(merkle_root_hash));
    values.insert("merkle_root_hash", root_hash_hex_string.as_str());

    values.insert("corpus_name", corpus_name);
    let mut corpus_description = CORPUS_DESCRIPTION.to_string();
    if corpus_desc.is_some() {
        corpus_description = corpus_desc.unwrap();
    }
    values.insert("corpus_description", &corpus_description);
    let mut corpus_motivation = CORPUS_MOTIVATION.to_string();
    if corpus_motiv.is_some() {
        corpus_motivation = corpus_motiv.unwrap();
    }
    values.insert("corpus_motivation", &corpus_motivation);
    let version_string = &AMBER_VERSION.to_string();
    values.insert("version", version_string);
    values.insert("version_date", AMBER_VERSION_DATE);
    let mut user_description = USER_DESCRIPTION.to_string();
    if user_desc.is_some() {
        user_description = user_desc.unwrap();
    }
    values.insert("user_description", &user_description);

    let tag_prefix = create_chain_tag_prefix(identifier, num_merkle_leaves, merkle_root_hash);
    let hex_tag_prefix_string = format!("{}", HexFmt(tag_prefix));
    values.insert("tag_prefix", &hex_tag_prefix_string.as_str());

    let text = template.try_fill_in(&values).unwrap().to_string();

    let mut file = match File::create(output_filename) {
        Ok(value) => value,
        Err(_) => return FailureReason::PathNotWriteable,
    };
    if file.write_all(&text.into_bytes()).is_err() {
        return FailureReason::PathNotWriteable
    };
    FailureReason::Success
}