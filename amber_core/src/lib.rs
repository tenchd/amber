pub mod merkle;
mod tag;
mod tests;
mod verify;

use hex_fmt::HexFmt;
use std::fs::File;
use std::io::{Write};
use std::path::PathBuf;
use walkdir::WalkDir;
use crate::merkle::{double_hash_from_file};
use crate::{
    merkle::{MerkleProof, MerkleTree, TimestampedMerkleTree}
};
use chrono::{DurationRound, TimeDelta, prelude::*};
extern crate rand;
use rand::{RngExt};

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

pub fn build_merkle_tree_from_directory(path: &str) -> (Option<MerkleTree>, FailureReason) {
    let filepaths = get_filenames_from_directory(path);
    println!("Building a Merkle tree from {} files. This may take a couple of minutes.", filepaths.len());
    //println!("{}", filepaths.first().unwrap());
    MerkleTree::new_from_files(filepaths.iter().map(|s| s.as_str()).collect())
}
pub fn build_doc_and_tag_from_saved_tree(tree_filename: &str, explain_filename: &str, tag_filename: &str, corpus_name: &str, utc_raw: DateTime<Utc>, locktime: usize, identifier: &str, corpus_desc: Option<String>, corpus_motiv: Option<String>, user_desc: Option<String>) -> FailureReason {
    println!("Reading merkle tree from file {}.", tree_filename);
    let (unfossilized_result, reason) = MerkleTree::new_from_unfinished_tree_file(tree_filename);
    if unfossilized_result.is_none() {
        return reason;
    }
    let unfossilized = unfossilized_result.unwrap();
    println!("Merkle tree has root hash: {}... and contains {} leaves", HexFmt(&unfossilized.get_root_hash()[..4]), unfossilized.num_leaves);
    unfossilized.verify_tree();

    let utc = utc_raw.duration_round(TimeDelta::try_minutes(15).unwrap()).unwrap();
    let date = format!("{}", utc.format("%B %e, %Y").to_string());
    let time = format!("{}", utc.format("%H:%M").to_string());

    let document_filename = explain_filename;
    crate::tag::write_document(document_filename, corpus_name, utc_raw, &date, &time, locktime, identifier, unfossilized.num_leaves.try_into().unwrap(), unfossilized.get_root_hash(), corpus_desc, corpus_motiv, user_desc);
    let (result, reason) = double_hash_from_file(document_filename);
    if result.is_none() {
        return reason
    }
    let document_hash = result.unwrap();
    let tag = crate::tag::create_chain_tag(identifier, unfossilized.num_leaves.try_into().unwrap(), unfossilized.get_root_hash(), document_hash);
    println!("Wrote explainer document to file {}", document_filename);
    //let tag_filename = "generated_timestamp/tag.txt";
    let tag_string = format!("{}", HexFmt(&tag));
    let file_result = File::create(tag_filename);
    if file_result.is_err() {
        println!("Failed to write tag to location {}", tag_filename);
        return FailureReason::PathNotWriteable;
    }
    let mut file = file_result.unwrap();
    let result = file.write_all(&tag_string.into_bytes());
    if result.is_err() {
        println!("Failed to write tag to location {}", tag_filename);
        return FailureReason::PathNotWriteable;
    }
    println!("Wrote tag to file {}", tag_filename);

    FailureReason::Success
}

pub fn build_timestamp(corpus_path: &str, hashes_path: &str, hashes_source: bool, tree_filename: &str, explain_filename: &str, tag_filename: &str, corpus_name: &str, locktime: usize, identifier: &str, corpus_desc: Option<String>, corpus_motiv: Option<String>, user_desc: Option<String>) -> (Option<MerkleTree>, FailureReason) {
    let tree: MerkleTree;
    if hashes_source {
        println!("Building merkle tree from leaf hashes in {}", hashes_path);
        let (result, reason) = MerkleTree::new_from_hashes(hashes_path);
        if result.is_none() {
            return (None, reason)
        }
        tree = result.unwrap();
    }
    else {
        let (tree_result, tree_reason) = build_merkle_tree_from_directory(corpus_path);
        if tree_result.is_none() {
            return (None, tree_reason)
        }
        tree = tree_result.unwrap();
        let reason = tree.write_leaf_hashes_to_file(hashes_path);
        if reason != FailureReason::Success {
            return (None, reason)
        }
    }
    let tree_filename_unfinished = format!("{}_unfinished.txt",tree_filename);
    println!("Merkle tree built. Root hash is {}", HexFmt(tree.get_root_hash()));

    let utc_raw = Utc::now();
    let utc = utc_raw.duration_round(TimeDelta::try_minutes(15).unwrap()).unwrap();
    let date = format!("{}", utc.format("%B%e, %Y").to_string());
    tree.write_unfinished_tree_to_file(&tree_filename_unfinished, &date);
    println!("wrote tree to file {}", tree_filename_unfinished);

    build_doc_and_tag_from_saved_tree(&tree_filename_unfinished, explain_filename, tag_filename, corpus_name, utc_raw, locktime, identifier, corpus_desc, corpus_motiv, user_desc);
    (Some(tree), FailureReason::Success)
}

pub fn finalize_timestamp(generated_tree_filename: &str, generated_explain_filename: &str, corpus_name: &str, identifier: &str, tx_hash: [u8; 32]) -> (Option<TimestampedMerkleTree>, FailureReason) {
    let unfinished_tree_file = format!("{}_unfinished.txt",generated_tree_filename);
    let (tree_result, reason) = MerkleTree::new_from_unfinished_tree_file(&unfinished_tree_file);
    if tree_result.is_none() {
        return (None, reason)
    }
    let unfinished_tree = tree_result.unwrap();
    let (result, reason) = double_hash_from_file(generated_explain_filename);
    if result.is_none() {
        return (None, reason);
    }
    let explain_hash = result.unwrap();
    let mut timestamped_tree = TimestampedMerkleTree::new_without_time(unfinished_tree, &identifier, tx_hash, explain_hash);
    println!("verifying tree file at {}", unfinished_tree_file);
    let autoaccept = false;
    let (result, reason) = timestamped_tree.verify_timestamp(generated_explain_filename, autoaccept);
    if result {
        timestamped_tree.fossilize_tree(generated_tree_filename, &corpus_name);

        println!("Timestamp verified! Wrote the updated merkle tree file at {}. Deleting temporary untimestamped merkle tree file at {}", generated_tree_filename, unfinished_tree_file);
        std::fs::remove_file(unfinished_tree_file).unwrap();
        return (Some(timestamped_tree), reason);
    }
    if autoaccept{
        println!("WARNING: you set the autoaccept flag to true so we did not actually verify w.r.t. the blockchain. This was for testing purposes only.");
    }
    (None, reason)
}

pub fn verify_tree(provided_tree_filename: &str, provided_explain_filename: &str) -> (bool, Option<TimestampedMerkleTree>, FailureReason) {
    println!("Verifying timestamp in {}", provided_tree_filename);
    let (timestamped_tree_result, reason) = TimestampedMerkleTree::new_from_fossilized_tree(&provided_tree_filename);
    if timestamped_tree_result.is_none() {
        return (false, None, reason);
    }
    let mut timestamped_tree = timestamped_tree_result.unwrap();
    let autoaccept = false;
    // remembering this timestamp value now because the verify_timestamp() function call will update the tree timestamp if they disagree.
    let tree_timestamp = timestamped_tree.utc_timestamp;
    let (mut result, mut reason) = timestamped_tree.verify_timestamp(&provided_explain_filename, autoaccept);
    //let mut difference = 0;
    let chain_utc_timestamp = timestamped_tree.utc_timestamp;
    if !result {
        println!("failed to verify");
    }
    else {
        let explain_utc_timestamp;
        // special case: If we're verifying the PG timestamp, we will hardcode a utc timestamp because that explain file did not include one. Since any other timestamp was made with Amber version >0.1, we can rely on its explain.txt file to have a utc timestamp on the second line of the file.
        let (hash_result, hash_reason) = double_hash_from_file(&provided_explain_filename);
        if hash_result.is_none() {
            return (false, None, hash_reason)
        }
        let hash = hash_result.unwrap();
        let explain_hash = format!("{}", HexFmt(hash));
        let pg_explain_hash = "deb4859fb5f483d0251cbe9ebe9908e0591a53511311ee07b134354eac324e22";
        if explain_hash == pg_explain_hash {
            explain_utc_timestamp = 1782492300;
        }
        else {
            explain_utc_timestamp = verify::get_explain_utc_timestamp(&provided_explain_filename);

        }
        let difference = chain_utc_timestamp - explain_utc_timestamp;
        println!("The estimated time listed in explain.txt and the exact timestamp recorded on the blockchain differ by {} seconds.", difference);
        let max_allowable_difference = 86400; // maximinum allowable difference between claimed timestamp and true timestamp is 24 hours.
        if difference > max_allowable_difference {
            result = false;
            reason = FailureReason::TimestampMismatchFatal;
        }
    }
    if reason == FailureReason::Success && tree_timestamp != chain_utc_timestamp {
        reason = FailureReason::TimestampMismatchNonFatal;
        println!("mismatch detected");
    }
    (result, Some(timestamped_tree), reason)
}

pub fn verify_file(tree_filename: &str, filepath: &str) -> bool {
    println!("Reading merkle tree from file {}.", tree_filename);
    let (unfossilized_result, reason) = TimestampedMerkleTree::new_from_fossilized_tree(tree_filename);
    if unfossilized_result.is_none() {
        println!("Could not load merkle tree for the following reason: {}", reason);
        return false;
    }
    let unfossilized = unfossilized_result.unwrap();
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

pub fn verify_proof(filepath: &str, proof_file: &str) -> (bool, FailureReason, i64, String, String, String, String, String) {
    let (proof, reason) = MerkleProof::new_from_file(proof_file);
    if proof.is_none() {
        let n = 0; // placeholder int
        let s = "".to_string(); // placeholder string
        return (false, reason, n, s.clone(), s.clone(), s.clone(), s.clone(), s.clone());
    }
    let proof = proof.unwrap();
    let (result, reason) = proof.verify_proof_for_file(filepath, false, true);
    let utc = chrono::DateTime::from_timestamp(proof.utc_timestamp, 0).unwrap();
    let date = format!("{}", utc.format("%B %e, %Y").to_string());
    let time = format!("{}", utc.format("%H:%M").to_string());
    let identifier = proof.identifier;
    if result {
        println!("File {} was verified by proof file {} via the Bitcoin blockchain.\nIts Merkle root hash {} appears in the Bitcoin transaction identified by tx hash {}.", filepath, proof_file, HexFmt(proof.root_hash), HexFmt(proof.tx_hash));

        println!("This proves that {} existed on {} at {}.", filepath, date, time);
    }
    else {
        println!("File {} failed to verify for proof file {}. It does NOT certify any timestamp for the file.", filepath, proof_file);
    }
    let tx_hash = HexFmt(proof.tx_hash).to_string();
    let block = proof.block_height.to_string();
    (result, reason, proof.utc_timestamp, tx_hash, block, date, time, identifier)
}

pub fn make_proof(input_path: &str, tree_filename: &str, explain_filename: &str, corpus_name: &str) -> (bool, FailureReason) {
    println!("Reading merkle tree from file {} and explain.txt from file {}.", tree_filename, explain_filename);
    let (result, unfossilized_result, reason) = verify_tree(tree_filename, explain_filename);
    if !result {
        return (false, reason);
    }
    //let (unfossilized_result, reason) = TimestampedMerkleTree::new_from_fossilized_tree(tree_filename);
    if unfossilized_result.is_none() {
        println!("Could not load merkle tree for the following reason: {}", reason);
        return (false, reason);
    }
    let unfossilized = unfossilized_result.unwrap();
    let md = std::fs::metadata(input_path).unwrap();
    // if user provided the path to a single file, create a proof for that file only.
    if md.is_file() {
        let output_filename = input_path.to_owned() + "_proof.txt";
        let (proof_result, reason) = unfossilized.produce_proof_from_file(input_path);
        if proof_result.is_none() {
            return (false, reason);
        }
        let proof = proof_result.unwrap();
        proof.fossilize_proof(&output_filename, corpus_name);
        proof.verify_proof_for_file(input_path, false, true);
        println!("{} Merkle proof written to file {}", input_path, output_filename);
        return (true, FailureReason::Success);
    }
    //if the user provided the path to a directory, create a proof for every file in that directory (recursively including subdirectories).
    else {
        println!("Producing merkle proofs for all files in directory {}", input_path);
        let filepaths = get_filenames_from_directory(input_path);
        println!("{} files found. Constructing proofs.", filepaths.len());
        let mut first = true;
        for filepath in filepaths {
            let output_filename = filepath.to_owned() + "_proof.txt";
            let (proof_result, reason) = unfossilized.produce_proof_from_file(&filepath);
            if proof_result.is_none() {
                return (false, reason);
            }
            let proof = proof_result.unwrap();
            proof.fossilize_proof(&output_filename, corpus_name);
            if first {
                let (blockchain_verified, _) = proof.verify_proof_for_file(&filepath, false, false);
                assert!(blockchain_verified, "Couldn't verify proof on blockchain. Aborting.");
                first = false;
            }
            else {
                let (local_verified, reason) = proof.verify_proof_for_file(&filepath, true, false);
                assert!(local_verified, "Proof file {} is invalid. Aborting.", filepath);
                return (false, reason);
            }
        }
        println!("Done writing proofs. Proof of file 'name.txt' is 'name.txt_proof.txt.'");
        return (true, FailureReason::Success);
    }
}

pub fn parse_hash_from_string(input_string: &str) -> (Option<[u8; 32]>, FailureReason) {
    merkle::parse_hash_from_str(input_string)
}

pub fn get_version_and_date() -> (String, String) {
    (AMBER_VERSION.to_string(), AMBER_VERSION_DATE.to_string())
}

pub fn slow_function() -> i64 {
    let mut sum = 0;
    println!("hi");
    for _ in 0..1000000000 {
        sum += rand::rng().random_range(0..10);
    }
    println!("done");
    sum
}

#[derive(PartialEq, Debug)]
pub enum FailureReason {
    Success, // a true success. checked everything about the timestamp and it all was correct.
    AutoAccept, // a fake success. here you check the local parts of the timestamp match each other but don't actually look at the blockchain.
    TimestampMismatchNonFatal, // the tag was found in the transaction, but the tx timestamp doesn't match the one listed in the tree/proof file.
    // this is a success technically because the timestamp WAS found, but the time listed in the file header may be significantly wrong.
    BlockHeightMismatchNonFatal,
    MerkleFileNotFound, // can't find merkle file
    MerkleFileNotParseable, // code can't read/parse merkle tree file
    ExplainFileNotParseable, // code can't read/parse explain file
    ProofFileNotParseable, // code can't read/parse merkle proof file
    ProofFileNotFound, // can't find proof file
    ExplainHashMismatch,  // double SHA256 hash of explain.txt doesn't match the header entry in merkle.txt
    ExplainFileNotFound, // can't find explain file
    FileHashMismatch, // double SHA256 hash of file provided alongside proof doesn't match first hash in proof leaf-> root path
    FileNotInMerkleTree, // the provided file is not in the merkle tree.
    FileNotFound, // can't find corpus file
    TxHashNotParseable, // the provided tx hash is not parseable; it's not 32 characters or has invalid characters.
    NoBlockchainResponse, // didn't get a response from the blockchain website (could be connectivity issue, or incorrect tx hash) 
    // in the future if you don't get a blockchain response, ping blockchain.info to see if the main page is up.
    TxNotFound, // the blockchain website didn't find a transaction with the supplied tx hash.
    TimestampMismatchFatal, // the tag was found in the transaction, but the chain utc timestamp is more than 24 hours different that the timestamp listed in explain.txt.
    TagNotFound, // the blockchain transaction doesn't contain an OP_RETURN script with the expected tag.
    PathNotWriteable, // you tried to write to some filepath that wasn't writeable for some reason.
} 

impl std::fmt::Display for FailureReason {
    fn fmt (&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FailureReason::Success => write!(f, "The timestamp was successfully verified."),
            FailureReason::AutoAccept => write!(f, "The timestamp was locally verified, but not checked on the blockchain."),
            FailureReason::TimestampMismatchNonFatal => write!(f, "While the timestamp verified successfully on the blockchain, the utc timestamp listed in the merkle tree file header is wrong; It does not match the true timestamp on the blockchain. This header value should be corrected."),
            FailureReason::BlockHeightMismatchNonFatal => write!(f, "While the timestamp verified successfully on the blockchain, the block height in the fossil file does not match the true block height of the transaction containing the timestamp. This header value should be corrected."),
            FailureReason::MerkleFileNotFound => write!(f, "The provided merkle tree file path could not be found."),
            FailureReason::MerkleFileNotParseable => write!(f, "The file containing the merkle tree could not be parsed."),
            FailureReason::ExplainFileNotParseable => write!(f, "Explain.txt could not be parsed."),
            FailureReason::ExplainFileNotFound => write!(f, "Could not find explain.txt."),
            FailureReason::ProofFileNotParseable => write!(f, "The provided proof file could not be parsed."),
            FailureReason::ProofFileNotFound => write!(f, "The provided proof file could not be found."),
            FailureReason::ExplainHashMismatch => write!(f, "The hash of explain.txt does not match the hash listed in the merkle/proof file header."),
            FailureReason::FileHashMismatch => write!(f, "The hash of the provided file does not match the expected hash in the proof file."),
            FailureReason::FileNotInMerkleTree => write!(f, "The provided file is not in the Merkle tree."),
            FailureReason::FileNotFound => write!(f, "The provided file could not be found."),
            FailureReason::TxHashNotParseable => write!(f, "The provided tx hash is invalid; it must contain only valid hex characters and be exactly 32 characters long."),
            FailureReason::NoBlockchainResponse => write!(f, "The blockchain lookup website did not respond to the request."),
            FailureReason::TxNotFound => write!(f, "The blockchain lookup website could not find a transaction with the specified tx hash."),
            FailureReason::TimestampMismatchFatal => write!(f, "The utc timestamp listed in explain.txt is > 24hrs different than utc timestamp on the blockchain."),
            FailureReason::TagNotFound => write!(f, "The expected timestamp message was not found in the blockchain transaction."),
            FailureReason::PathNotWriteable => write!(f, "Couldn't write output file at the specified location."),

        }
    }
}

pub struct Session {
    pub tstree: Option<TimestampedMerkleTree>,
    pub uftree: Option<MerkleTree>,
    pub tree_filename: Option<PathBuf>,
    pub explain_filename: Option<PathBuf>,
    pub tag_filename: Option<PathBuf>,
    pub auth_filename: Option<PathBuf>,
    pub timestamp_output_path: Option<PathBuf>,
    pub source_dir_path: Option<PathBuf>,
    pub hashes_path: Option<PathBuf>,
}

impl Session {
    pub fn new() -> Self {
        Self {
            tstree: None,
            uftree: None,
            tree_filename: None,
            explain_filename: None,
            tag_filename: None,
            auth_filename: None,
            timestamp_output_path: None,
            source_dir_path: None,
            hashes_path: None,
        }
    }

    pub fn finalize_timestamp(&mut self, generated_tree_filename: &str, generated_explain_filename: &str, corpus_name: &str, identifier: &str, tx_hash: [u8; 32]) -> (bool, FailureReason) {
        self.uftree = None;

        let reason;
        
        (self.tstree, reason) = finalize_timestamp(generated_tree_filename, generated_explain_filename, corpus_name, identifier, tx_hash);

        if self.tstree.is_some() {
            return (true, reason);
        }
        (false, reason)
    }

    pub fn parse_hash(input_string: &str) -> (Option<[u8; 32]>, FailureReason) {

        merkle::parse_hash_from_str(input_string)
    }

    pub fn get_locktime() -> (Option<usize>, FailureReason) {
        let (result, reason) = verify::get_current_latest_block();
        if result.is_none() {
            return (None, reason)
        }
        let block_height = result.unwrap();
        (Some(block_height + 1), FailureReason::Success)
    }
}

pub fn verify_tree_async(tree_filename: PathBuf, explain_filename: PathBuf) -> (bool, Option<TimestampedMerkleTree>, FailureReason) {
    let tree_path = tree_filename.to_str().unwrap();
    let explain_path = explain_filename.to_str().unwrap();
    let (result, tree, reason) = verify_tree(tree_path, explain_path);

    (result, tree, reason)
}

pub fn verify_proof_async(filepath: PathBuf, proof_filepath: PathBuf) -> (bool, FailureReason, i64, String, String, String, String, String) {
    let path = filepath.to_str().unwrap();
    let proof_path = proof_filepath.to_str().unwrap();
    verify_proof(path, proof_path)
}

pub fn build_proof_async(file_path: PathBuf, merkle_path: PathBuf, explain_path: PathBuf, corpus_name: &str) -> (bool, FailureReason) {
    let path = file_path.to_str().unwrap();
    let merkle = merkle_path.to_str().unwrap();
    let explain = explain_path.to_str().unwrap();
    make_proof(path, merkle, explain, corpus_name)
}

pub fn build_timestamp_async(corpus_name: String, identifier: String, hashes_source: bool, input_hashes_path: Option<PathBuf>, input_source_dir: Option<PathBuf>, corpus_desc: String, corpus_motiv: String, user_desc: String, timestamp_output_path: PathBuf) -> (bool, Option<MerkleTree>, FailureReason, Option<PathBuf>, Option<PathBuf>, Option<PathBuf>) {
    let (locktime_result, locktime_reason) = Session::get_locktime();
    if locktime_result.is_none() {
        return (false, None, locktime_reason, None, None, None)
    }
    let locktime = locktime_result.unwrap();

    let mut output_dir = timestamp_output_path;
    output_dir.push("merkle.txt");
    let tree_filename_buf = output_dir.clone();
    let tree_filename = tree_filename_buf.to_str().unwrap();
    output_dir.pop();

    output_dir.push("explain.txt");
    let explain_filename_buf = output_dir.clone();
    let explain_filename = explain_filename_buf.to_str().unwrap();
    output_dir.pop();

    output_dir.push("tag.txt");
    let tag_filename_buf = output_dir.clone();
    let tag_filename = tag_filename_buf.to_str().unwrap();
    output_dir.pop();

    output_dir.push("leaf_hashes.txt");
    let leaf_hash_filename_buf = output_dir.clone();
    let leaf_hash_filename = leaf_hash_filename_buf.to_str().unwrap();
    output_dir.pop();

    //let output_path = self.timestamp_output_path.as_ref().unwrap().to_str().unwrap();
    let mut corpus_path = "";
    let hashes_path;

    if hashes_source {
        hashes_path = input_hashes_path.as_ref().unwrap().to_str().unwrap();
    }
    else {
        corpus_path = input_source_dir.as_ref().unwrap().to_str().unwrap();
        hashes_path = leaf_hash_filename;
    }

    let (result, reason) = build_timestamp(corpus_path, hashes_path, hashes_source, tree_filename, explain_filename, tag_filename, &corpus_name, locktime, &identifier, Some(corpus_desc), Some(corpus_motiv), Some(user_desc));
    if result.is_none() {
        return (false, None, reason, None, None, None);
    }
    (true, result, FailureReason::Success, Some(PathBuf::from(tree_filename)), Some(PathBuf::from(explain_filename)), Some(PathBuf::from(tag_filename)))
}

pub fn finalize_timestamp_async(generated_tree_filename: PathBuf, generated_explain_filename: PathBuf, corpus_name: &str, identifier: &str, tx_hash: [u8; 32]) -> (bool, Option<TimestampedMerkleTree>, FailureReason) {

    let tree_path = generated_tree_filename.to_str().unwrap();
    let explain_path = generated_explain_filename.to_str().unwrap();
    
    let (tree, reason) = finalize_timestamp(tree_path, explain_path, corpus_name, identifier, tx_hash);

    if tree.is_some() {
        return (true, tree, reason);
    }
    (false, None, reason)
}