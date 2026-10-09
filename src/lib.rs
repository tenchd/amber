mod merkle;
mod tag;
mod tests;
mod verify;

use hex_fmt::HexFmt;
use std::fs::File;
use std::io::{Write};
use walkdir::WalkDir;
use crate::merkle::{double_hash_from_file};
use crate::{
    merkle::{MerkleProof, MerkleTree, TimestampedMerkleTree}
};
use chrono::{DurationRound, TimeDelta, prelude::*};

const AMBER_VERSION: &str = "0.1.0";
const AMBER_VERSION_DATE: &str = "Sept 25, 2026";

// Scans corpus top-level directory recursively to gather the files that will be put in the merkle tree.
pub fn get_filenames_from_directory(path: &str) -> Vec<String> {
    let filepaths: Vec<String> = WalkDir::new(path)
        .into_iter()
        //.expect("Failed to read directory")
        .filter_map(|entry| {
            let entry = entry.expect("Failed to read directory entry");
            if !entry.file_type().is_dir() {
                Some(entry.path().to_str().unwrap().to_string())
            }
            else {
                Option::None
            }
        })
        .collect();
    filepaths
}

pub fn build_merkle_tree_from_directory(path: &str) -> MerkleTree {
    let filepaths = get_filenames_from_directory(path);
    println!("Building a Merkle tree from {} files. This may take a couple of minutes.", filepaths.len());
    //println!("{}", filepaths.first().unwrap());
    MerkleTree::new_from_files(filepaths.iter().map(|s| s.as_str()).collect())
}
pub fn build_doc_and_tag_from_saved_tree(tree_filename: &str, explain_filename: &str, tag_filename: &str, corpus_name: &str, utc_raw: DateTime<Utc>, locktime: usize, identifier: &str){
    println!("Reading merkle tree from file {}.", tree_filename);
    let unfossilized: MerkleTree = MerkleTree::new_from_unfinished_tree_file(tree_filename);
    println!("Merkle tree has root hash: {}... and contains {} leaves", HexFmt(&unfossilized.get_root_hash()[..4]), unfossilized.num_leaves);
    unfossilized.verify_tree();


    let utc = utc_raw.duration_round(TimeDelta::try_minutes(15).unwrap()).unwrap();
    let date = format!("{}", utc.format("%B %e, %Y").to_string());
    let time = format!("{}", utc.format("%H:%M").to_string());

    let document_filename = explain_filename;
    crate::tag::write_document(document_filename, corpus_name, utc_raw, &date, &time, locktime, identifier, unfossilized.num_leaves.try_into().unwrap(), unfossilized.get_root_hash());
    let document_hash = double_hash_from_file(document_filename);
    let tag = crate::tag::create_chain_tag(identifier, unfossilized.num_leaves.try_into().unwrap(), unfossilized.get_root_hash(), document_hash);
    println!("Wrote explainer document to file {}", document_filename);
    //let tag_filename = "generated_timestamp/tag.txt";
    let tag_string = format!("{}", HexFmt(&tag));
    let mut file = File::create(tag_filename).expect("failed to create file");
    file.write_all(&tag_string.into_bytes()).expect("failed to write tag");
    println!("Wrote tag to file {}", tag_filename);
}

pub fn build_timestamp(corpus_path: &str, hashes_path: &str, hashes_source: bool, tree_filename: &str, explain_filename: &str, tag_filename: &str, corpus_name: &str, locktime: usize, identifier: &str) {
    let mut _tree = MerkleTree::new_empty();
    if hashes_source {
        println!("Building merkle tree from leaf hashes in {}", hashes_path);
        _tree = MerkleTree::new_from_hashes(hashes_path);
    }
    else {
        _tree = build_merkle_tree_from_directory(corpus_path);
        _tree.write_leaf_hashes_to_file(hashes_path);
    }
    let tree_filename_unfinished = format!("{}_unfinished.txt",tree_filename);
    println!("Merkle tree built. Root hash is {}", HexFmt(_tree.get_root_hash()));

    let utc_raw = Utc::now();
    let utc = utc_raw.duration_round(TimeDelta::try_minutes(15).unwrap()).unwrap();
    let date = format!("{}", utc.format("%B%e, %Y").to_string());
    _tree.write_unfinished_tree_to_file(&tree_filename_unfinished, &date);
    println!("wrote tree to file {}", tree_filename_unfinished);

    build_doc_and_tag_from_saved_tree(&tree_filename_unfinished, explain_filename, tag_filename, corpus_name, utc_raw, locktime, identifier);
}

pub fn finalize_timestamp(generated_tree_filename: &str, generated_explain_filename: &str, corpus_name: &str, identifier: &str, tx_hash: [u8; 32]) {
    let unfinished_tree_file = format!("{}_unfinished.txt",generated_tree_filename);
    let unfinished_tree = MerkleTree::new_from_unfinished_tree_file(&unfinished_tree_file);
    let explain_hash = double_hash_from_file(generated_explain_filename);
    let mut timestamped_tree = TimestampedMerkleTree::new_without_time(unfinished_tree, &identifier, tx_hash, explain_hash);
    println!("verifying tree file at {}", unfinished_tree_file);
    let autoaccept = false;
    let result = timestamped_tree.verify_timestamp(generated_explain_filename, autoaccept);
    if result {
        timestamped_tree.fossilize_tree(generated_tree_filename, &corpus_name);

        println!("Timestamp verified! Wrote the updated merkle tree file at {}. Deleting temporary untimestamped merkle tree file at {}", generated_tree_filename, unfinished_tree_file);
        std::fs::remove_file(unfinished_tree_file).unwrap();
    }
    if autoaccept{
        println!("WARNING: you set the autoaccept flag to true so we did not actually verify w.r.t. the blockchain. This was for testing purposes only.");
    }
}

pub fn verify_tree(provided_tree_filename: &str, provided_explain_filename: &str) -> (bool, String, String, String, String, String) {
    println!("Verifying timestamp in {}", provided_tree_filename);
    let mut timestamped_tree = TimestampedMerkleTree::new_from_fossilized_tree(&provided_tree_filename);
    let autoaccept = false;
    let result = timestamped_tree.verify_timestamp(&provided_explain_filename, autoaccept);
    let mut difference = 0;
    if !result {
        println!("failed to verify");
    }
    else {
        let chain_utc_timestamp = timestamped_tree.utc_timestamp;
        let mut _explain_utc_timestamp = 0;
        // special case: If we're verifying the PG timestamp, we will hardcode a utc timestamp because that explain file did not include one. Since any other timestamp was made with Amber version >0.1, we can rely on its explain.txt file to have a utc timestamp on the second line of the file.
        let explain_hash = format!("{}", HexFmt(double_hash_from_file(&provided_explain_filename)));
        let pg_explain_hash = "deb4859fb5f483d0251cbe9ebe9908e0591a53511311ee07b134354eac324e22";
        if explain_hash == pg_explain_hash {
            _explain_utc_timestamp = 1782492300;
        }
        else {
            _explain_utc_timestamp = verify::get_explain_utc_timestamp(&provided_explain_filename);
        }
        difference = chain_utc_timestamp - _explain_utc_timestamp;
        println!("The estimated time listed in explain.txt and the exact timestamp recorded on the blockchain differ by {} seconds.", difference);
    }
    let tx_hash = timestamped_tree.tx_hash;
    let block = timestamped_tree.block_height;
    let utc = chrono::DateTime::from_timestamp(timestamped_tree.utc_timestamp, 0).unwrap();
    let date = format!("{}", utc.format("%B %e, %Y").to_string());
    let time = format!("{}", utc.format("%H:%M").to_string());
    (result, HexFmt(tx_hash).to_string(), block.to_string(), date, time, difference.to_string())
}

pub fn verify_file(tree_filename: &str, filepath: &str) -> bool {
    println!("Reading merkle tree from file {}.", tree_filename);
    let unfossilized: TimestampedMerkleTree = TimestampedMerkleTree::new_from_fossilized_tree(tree_filename);
    println!("Merkle tree has root hash: {}... and contains {} leaves", HexFmt(&unfossilized.tree.get_root_hash()[..4]), unfossilized.tree.num_leaves);
    unfossilized.tree.verify_tree();

    let contains = unfossilized.tree.verify_from_file(filepath);
    if contains {
        println!("{} is in the Merkle tree.", filepath);
    }
    else {
        println!("{} is NOT in the Merkle tree.", filepath);
    }
    contains
}

pub fn verify_proof(filepath: &str, proof_file: &str) -> (bool, String, String, String, String) {
    let proof = MerkleProof::new_from_file(proof_file);
    let result = proof.verify_proof_for_file(filepath, false, true);
    let utc = chrono::DateTime::from_timestamp(proof.utc_timestamp, 0).unwrap();
    let date = format!("{}", utc.format("%B %e, %Y").to_string());
    let time = format!("{}", utc.format("%H:%M").to_string());
    if result {
        println!("File {} was verified by proof file {} via the Bitcoin blockchain.\nIts Merkle root hash {} appears in the Bitcoin transaction identified by tx hash {}.", filepath, proof_file, HexFmt(proof.root_hash), HexFmt(proof.tx_hash));

        println!("This proves that {} existed on {} at {}.", filepath, date, time);
    }
    else {
        println!("File {} failed to verify for proof file {}. It does NOT certify any timestamp for the file.", filepath, proof_file);
    }
    let tx_hash = HexFmt(proof.tx_hash).to_string();
    let block = proof.block_height.to_string();
    (result, tx_hash, block, date, time)
}

pub fn make_proof(input_path: &str, tree_filename: &str, corpus_name: &str) {
    println!("Reading merkle tree from file {}.", tree_filename);
    let unfossilized: TimestampedMerkleTree = TimestampedMerkleTree::new_from_fossilized_tree(tree_filename);
    let md = std::fs::metadata(input_path).unwrap();
    // if user provided the path to a single file, create a proof for that file only.
    if md.is_file() {
        let output_filename = input_path.to_owned() + "_proof.txt";
        let proof = unfossilized.produce_proof_from_file(input_path);
        proof.fossilize_proof(&output_filename, corpus_name);
        proof.verify_proof_for_file(input_path, false, true);
        println!("{} Merkle proof written to file {}", input_path, output_filename);
    }
    //if the user provided the path to a directory, create a proof for every file in that directory (recursively including subdirectories).
    else {
        println!("Producing merkle proofs for all files in directory {}", input_path);
        let filepaths = get_filenames_from_directory(input_path);
        println!("{} files found. Constructing proofs.", filepaths.len());
        let mut first = true;
        for filepath in filepaths {
            let output_filename = filepath.to_owned() + "_proof.txt";
            let proof = unfossilized.produce_proof_from_file(&filepath);
            proof.fossilize_proof(&output_filename, corpus_name);
            if first {
                let blockchain_verified = proof.verify_proof_for_file(&filepath, false, false);
                assert!(blockchain_verified, "Couldn't verify proof on blockchain. Aborting.");
                first = false;
            }
            else {
                let local_verified = proof.verify_proof_for_file(&filepath, true, false);
                assert!(local_verified, "Proof file {} is invalid. Aborting.", filepath);
            }
        }
        println!("Done writing proofs. Proof of file 'name.txt' is 'name.txt_proof.txt.'");
    }
}

pub fn parse_hash_from_string(input_string: &str) -> [u8; 32]{
    merkle::parse_hash_from_str(input_string)
}