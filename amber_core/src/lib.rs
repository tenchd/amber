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
use bitcoin::{Address, Network, address::NetworkUnchecked};

const AMBER_VERSION: &str = "0.1.0";
const AMBER_VERSION_DATE: &str = "Sept 25, 2026";

const EXPLAIN_TEMPLATE: &str = include_str!("../fixed_templates/explain_template.txt");
const MERKLE_TEMPLATE: &str = include_str!("../fixed_templates/merkle_template.txt");
const UNFINISHED_MERKLE_TEMPLATE: &str = include_str!("../fixed_templates/unfinished_merkle_template.txt");
const PROOF_TEMPLATE: &str = include_str!("../fixed_templates/proof_template.txt");
const CORPUS_DESCRIPTION: &str = include_str!("../editable_templates/corpus_description.txt");
const CORPUS_MOTIVATION: &str = include_str!("../editable_templates/corpus_motivation.txt");
const USER_DESCRIPTION: &str = include_str!("../editable_templates/user_description.txt");

// Scans corpus top-level directory recursively to gather the files that will be put in the merkle tree.
pub fn get_filenames_from_directory(path: &PathBuf) -> Vec<PathBuf> {
    let filepaths: Vec<PathBuf> = WalkDir::new(path)
        .into_iter()
        //.expect("Failed to read directory")
        .filter_map(|entry| {
            let entry = entry.expect("Failed to read directory entry");
            if entry.file_type().is_file() && !entry.path().to_string_lossy().ends_with("_proof.txt") {
                Some(entry.into_path())
            }
            else {
                Option::None
            }
        })
        .collect();
    filepaths
}

pub fn build_merkle_tree_from_directory(path: &PathBuf) -> Result<MerkleTree, FailureReason> {
    let filepaths = get_filenames_from_directory(path);
    if filepaths.len() == 0 {
        println!("Directory contains no timestampable files.");
        return Err(FailureReason::EmptyCorpus)
    }
    println!("Building a Merkle tree from {} files. This may take a couple of minutes.", filepaths.len());
    MerkleTree::new_from_files(filepaths)
}
pub fn build_doc_and_tag_from_saved_tree(tree_filename: &PathBuf, explain_filename: &PathBuf, tag_filename: &PathBuf, corpus_name: &str, utc_raw: DateTime<Utc>, locktime: usize, identifier: &str, corpus_desc: Option<String>, corpus_motiv: Option<String>, user_desc: Option<String>) -> Result<Vec<Warning>, FailureReason> {
    println!("Reading merkle tree from file {}.", tree_filename.to_string_lossy());
    let (unfossilized, warnings) = MerkleTree::new_from_unfinished_tree_file(tree_filename)?;
    println!("Merkle tree has root hash: {}... and contains {} leaves", HexFmt(&unfossilized.get_root_hash()[..4]), unfossilized.num_leaves);
    unfossilized.verify_tree();

    let utc = utc_raw.duration_round(TimeDelta::try_minutes(15).unwrap()).unwrap();
    let date = format!("{}", utc.format("%B %-d, %Y").to_string());
    let time = format!("{}", utc.format("%H:%M").to_string());

    let document_filename = explain_filename;
    crate::tag::write_document(&document_filename, corpus_name, utc_raw, &date, &time, locktime, identifier, unfossilized.num_leaves.try_into().unwrap(), unfossilized.get_root_hash(), corpus_desc, corpus_motiv, user_desc);
    let document_hash = double_hash_from_file(&document_filename)?;
    let tag = crate::tag::create_chain_tag(identifier, unfossilized.num_leaves.try_into().unwrap(), unfossilized.get_root_hash(), document_hash);
    println!("Wrote explainer document to file {}", document_filename.to_string_lossy());
    //let tag_filename = "generated_timestamp/tag.txt";
    let tag_string = format!("{}", HexFmt(&tag));
    let file_result = File::create(&tag_filename);
    if file_result.is_err() {
        println!("Failed to write tag to location {}", tag_filename.to_string_lossy());
        return Err(FailureReason::PathNotWriteable);
    }
    let mut file = file_result.unwrap();
    let result = file.write_all(&tag_string.into_bytes());
    if result.is_err() {
        println!("Failed to write tag to location {}", tag_filename.to_string_lossy());
        return Err(FailureReason::PathNotWriteable);
    }
    println!("Wrote tag to file {}", tag_filename.to_string_lossy());

    Ok(warnings)
}

fn append_to_filename(filename: &PathBuf, extension: &str) -> PathBuf {
    let mut tree_filename_unfinished: PathBuf = Default::default();
    if let Some(prefix) = filename.file_name() {
        let mut unfinished_filename = prefix.to_os_string();
        unfinished_filename.push(extension);
        tree_filename_unfinished.set_file_name(unfinished_filename);
    }
    //tree_filename_unfinished
    let mut result = filename.clone();
    result.pop();
    result.push(tree_filename_unfinished);
    result
}

pub fn build_timestamp(corpus_path: &PathBuf, hashes_path: &PathBuf, hashes_source: bool, tree_filename: &PathBuf, explain_filename: &PathBuf, tag_filename: &PathBuf, corpus_name: &str, locktime: usize, identifier: &str, corpus_desc: Option<String>, corpus_motiv: Option<String>, user_desc: Option<String>) -> Result<(MerkleTree, Vec<Warning>), FailureReason> {

    println!("{}", tree_filename.to_string_lossy());
    // ensure that the identifier string is entirely graphic ASCII characters
    let mut identifier_graphic = true;
    for character in identifier.chars() {
        identifier_graphic = identifier_graphic && character.is_ascii_graphic();
    }

    // ensure identifier is exactly 8 characters long
    let identifier_valid = identifier.len() == 8 && identifier_graphic;

    if !identifier_valid {
        return Err(FailureReason::InvalidIdentifier);
    }

    let tree;
    let mut warnings;

    if hashes_source {
        println!("Building merkle tree from leaf hashes in {}", hashes_path.to_string_lossy());
        (tree, warnings) = MerkleTree::new_from_hashes(hashes_path)?;
    }
    else {
        tree = build_merkle_tree_from_directory(corpus_path)?;
        tree.write_leaf_hashes_to_file(hashes_path)?;
        warnings = vec![];
    }

    let tree_filename_unfinished = append_to_filename(tree_filename, "_unfinished.txt");

    println!("Merkle tree built. Root hash is {}", HexFmt(tree.get_root_hash()));

    let utc_raw = Utc::now();
    let utc = utc_raw.duration_round(TimeDelta::try_minutes(15).unwrap()).unwrap();
    let date = format!("{}", utc.format("%B %-d, %Y").to_string());
    tree.write_unfinished_tree_to_file(&tree_filename_unfinished, &date)?;
    println!("wrote tree to file {}", tree_filename_unfinished.to_string_lossy());

    let other_warnings = build_doc_and_tag_from_saved_tree(&tree_filename_unfinished, explain_filename, tag_filename, corpus_name, utc_raw, locktime, identifier, corpus_desc, corpus_motiv, user_desc)?;
    warnings.extend(other_warnings);
    Ok((tree, warnings))
}

pub fn finalize_timestamp(generated_tree_filename: &PathBuf, generated_explain_filename: &PathBuf, corpus_name: &str, identifier: &str, tx_hash: [u8; 32]) -> Result<(TimestampedMerkleTree, Vec<Warning>), FailureReason> {
    let unfinished_tree_file = append_to_filename(generated_tree_filename, "_unfinished.txt");
    let (unfinished_tree, tree_warnings) = MerkleTree::new_from_unfinished_tree_file(&unfinished_tree_file)?;
    let explain_hash = double_hash_from_file(generated_explain_filename)?;
    let mut timestamped_tree = TimestampedMerkleTree::new_without_time(unfinished_tree, &identifier, tx_hash, explain_hash);
    println!("verifying tree file at {}", unfinished_tree_file.to_string_lossy());
    let autoaccept = false;
    let mut timestamp_warnings = timestamped_tree.verify_timestamp(generated_explain_filename, autoaccept)?;
    timestamped_tree.fossilize_tree(generated_tree_filename, &corpus_name)?;

    println!("Timestamp verified! Wrote the updated merkle tree file at {}. Deleting temporary untimestamped merkle tree file at {}", generated_tree_filename.to_string_lossy(), unfinished_tree_file.to_string_lossy());
    std::fs::remove_file(unfinished_tree_file).unwrap();

    timestamp_warnings.extend(tree_warnings);
    return Ok((timestamped_tree, timestamp_warnings));
}

pub fn verify_tree(provided_tree_filename: &PathBuf, provided_explain_filename: &PathBuf) -> Result<(TimestampedMerkleTree, Vec<Warning>), FailureReason> {
    println!("Verifying timestamp in {}", provided_tree_filename.to_string_lossy());
    let mut warnings = vec![];
    let (mut timestamped_tree, tree_warnings) = TimestampedMerkleTree::new_from_fossilized_tree(&provided_tree_filename)?;
    warnings.extend(tree_warnings);
    let autoaccept = false;
    // remembering this timestamp value now because the verify_timestamp() function call will update the tree timestamp if they disagree.
    let tree_timestamp = timestamped_tree.utc_timestamp;
    let verify_warnings = timestamped_tree.verify_timestamp(&provided_explain_filename, autoaccept)?;
    warnings.extend(verify_warnings);
    //let mut difference = 0;
    let chain_utc_timestamp = timestamped_tree.utc_timestamp;
    let explain_utc_timestamp;
    // special case: If we're verifying the PG timestamp, we will hardcode a utc timestamp because that explain file did not include one. Since any other timestamp was made with Amber version >0.1, we can rely on its explain.txt file to have a utc timestamp on the second line of the file.
    let hash = double_hash_from_file(&provided_explain_filename)?;
    let explain_hash = format!("{}", HexFmt(hash));
    let pg_explain_hash = "deb4859fb5f483d0251cbe9ebe9908e0591a53511311ee07b134354eac324e22";
    if explain_hash == pg_explain_hash {
        explain_utc_timestamp = 1782492300;
    }
    else {
        explain_utc_timestamp = verify::get_explain_utc_timestamp(&provided_explain_filename)?;
    }
    let difference = (chain_utc_timestamp - explain_utc_timestamp).abs();
    println!("The estimated time listed in explain.txt and the exact timestamp recorded on the blockchain differ by {} seconds.", difference);
    let max_allowable_difference = 86400; // maximinum allowable difference between claimed timestamp and true timestamp is 24 hours.
    if difference > max_allowable_difference {
        return Err(FailureReason::TimestampMismatchFatal);
    }
    if tree_timestamp != chain_utc_timestamp {
        warnings.push(Warning::TimestampMismatchNonFatal);
    }
    Ok((timestamped_tree, warnings))
}

pub fn verify_file(tree_filename: &PathBuf, filepath: &PathBuf) -> Result<(bool, Vec<Warning>), FailureReason> {
    println!("Reading merkle tree from file {}.", tree_filename.to_string_lossy());
    let (unfossilized, timestamp_warnings) = TimestampedMerkleTree::new_from_fossilized_tree(tree_filename)?;
    println!("Merkle tree has root hash: {}... and contains {} leaves", HexFmt(&unfossilized.tree.get_root_hash()[..4]), unfossilized.tree.num_leaves);
    unfossilized.tree.verify_tree();

    let contains = unfossilized.tree.verify_from_file(filepath)?;
    if contains {
        println!("{} is in the Merkle tree.", filepath.to_string_lossy());
    }
    else {
        println!("{} is NOT in the Merkle tree.", filepath.to_string_lossy());
    }
    Ok((contains, timestamp_warnings))
}
//        return (result, reason, Some(utc_secs), tx_hash, block, Some(date), Some(time), identifier);
pub struct ProofVerifyDetails {
    pub verified: bool,
    pub warnings: Vec<Warning>,
    pub utc_timestamp: i64,
    pub tx_hash: String,
    pub block: String,
    pub date: String,
    pub time: String,
    pub identifier: String,
}


pub fn verify_proof(filepath: &PathBuf, proof_file: &PathBuf) -> Result<ProofVerifyDetails, FailureReason> {
    let proof = MerkleProof::new_from_file(proof_file)?;
    let (chain_timestamp, chain_block_height, warnings) = proof.verify_proof_for_file(filepath, false, true)?;
    let identifier = proof.identifier;
    let block;
    let tx_hash = HexFmt(proof.tx_hash).to_string();
    let utc = match chrono::DateTime::from_timestamp(chain_timestamp.unwrap(), 0) {
        Some(value) => value,
        None => return Err(FailureReason::UnexpectedBlockchainResponse),
    };
    let date = format!("{}", utc.format("%B %-d, %Y").to_string());
    let time = format!("{}", utc.format("%H:%M").to_string());
    println!("File {} was verified by proof file {} via the Bitcoin blockchain.\nIts Merkle root hash {} appears in the Bitcoin transaction identified by tx hash {}.", filepath.to_string_lossy(), proof_file.to_string_lossy(), HexFmt(proof.root_hash), HexFmt(proof.tx_hash));

    println!("This proves that {} existed on {} at {}.", filepath.to_string_lossy(), date, time);
    block = chain_block_height.unwrap().to_string();
    let utc_secs: i64 = utc.timestamp();
    return Ok(ProofVerifyDetails { verified: true, warnings, utc_timestamp: utc_secs, tx_hash, block, date, time, identifier})
    // else {
    //     block = proof.block_height.to_string();
    //     println!("File {} failed to verify for proof file {}. It does NOT certify any timestamp for the file.", filepath.to_string_lossy(), proof_file.to_string_lossy());

    //     return (result, reason, Some(proof.utc_timestamp), tx_hash, block, None, None, identifier)
    // }

}

pub fn make_proof(input_path: &PathBuf, tree_filename: &PathBuf, explain_filename: &PathBuf, corpus_name: &str) -> Result<Vec<Warning>, FailureReason> {
    println!("Reading merkle tree from file {} and explain.txt from file {}.", tree_filename.to_string_lossy(), explain_filename.to_string_lossy());
    let mut warnings = vec![];
    let (unfossilized, tree_warnings) = verify_tree(tree_filename, explain_filename)?;
    warnings.extend(tree_warnings);
    let md = match std::fs::metadata(input_path) {
        Ok(value) => value,
        Err(err) => return Err(FailureReason::Internal(err.to_string())), 
    };
    // if user provided the path to a single file, create a proof for that file only.
    if md.is_file() {
        let output_filename = append_to_filename(input_path, "_proof.txt");
        let proof = unfossilized.produce_proof_from_file(input_path)?;
        proof.fossilize_proof(&output_filename, corpus_name)?;
        proof.verify_proof_for_file(input_path, false, true)?;
        println!("{} Merkle proof written to file {}", input_path.to_string_lossy(), output_filename.to_string_lossy());
        return Ok(warnings);
    }
    //if the user provided the path to a directory, create a proof for every file in that directory (recursively including subdirectories).
    else {
        println!("Producing merkle proofs for all files in directory {}", input_path.to_string_lossy());
        let filepaths = get_filenames_from_directory(input_path);
        println!("{} files found. Constructing proofs.", filepaths.len());
        let mut first = true;
        for filepath in filepaths {
            let output_filename = append_to_filename(&filepath, "_proof.txt");
            let proof = unfossilized.produce_proof_from_file(&filepath)?;
            proof.fossilize_proof(&output_filename, corpus_name)?;
            if first {
                let (_, _, first_proof_warnings) = proof.verify_proof_for_file(&filepath, false, false)?;
                warnings.extend(first_proof_warnings);
                first = false;
            }
            else {
                let (_, _, _) = proof.verify_proof_for_file(&filepath, true, false)?;
            }
        }
        println!("Done writing proofs. Proof of file 'name.txt' is 'name.txt_proof.txt.'");
        Ok(warnings)
    }
}

pub fn parse_hash_from_string(input_string: &str) -> Result<[u8; 32], FailureReason> {
    merkle::parse_hash_from_str(input_string)
}

pub fn get_version_and_date() -> (String, String) {
    (AMBER_VERSION.to_string(), AMBER_VERSION_DATE.to_string())
}

#[derive(PartialEq, Debug)]
pub enum FailureReason {
    Success, // a true success. checked everything about the timestamp and it all was correct.
    EmptyCorpus, // provided directory has no timestampable files
    MerkleFileNotFound(String), // can't find merkle file
    MerkleFileNotParseable(usize), // code can't read/parse merkle tree file
    MerkleTreeInconsistent, // merkle tree from file isn't valid
    LeafHashesFileNotFound(String), // can't find leaf hashes file
    ExplainFileNotParseable(usize), // code can't read/parse explain file
    ProofFileNotParseable(usize), // code can't read/parse merkle proof file
    ProofFileNotFound(String), // can't find proof file
    ProofWrongLength(usize, usize), // proof has the wrong length of leaf-> root path
    ExplainHashMismatch,  // double SHA256 hash of explain.txt doesn't match the header entry in merkle.txt
    ExplainFileNotFound(String), // can't find explain file
    FileHashMismatch, // double SHA256 hash of file provided alongside proof doesn't match first hash in proof leaf-> root path
    FileNotInMerkleTree, // the provided file is not in the merkle tree.
    FileNotFound, // can't find corpus file
    FileReadError(String), // error when reading file
    InvalidIdentifier, // provided identifier is not 8 (non-whitespace or control) ASCII characters
    TxHashNotParseable, // the provided tx hash is not parseable; it's not 32 characters or has invalid characters.
    NoBlockchainResponse, // didn't get a response from the blockchain website (could be connectivity issue, or incorrect tx hash) 
    // in the future if you don't get a blockchain response, ping blockchain.info to see if the main page is up.
    TxNotFound, // the blockchain website didn't find a transaction with the supplied tx hash.
    TxUnconfirmed, // the blockchain transaction hasn't been mined into a block yet.
    TimestampMismatchFatal, // the tag was found in the transaction, but the chain utc timestamp is more than 24 hours different that the timestamp listed in explain.txt.
    UnexpectedBlockchainResponse, // the blockchain's response is weird in some way that the other failures don't address.
    TagNotFound, // the blockchain transaction doesn't contain an OP_RETURN script with the expected tag.
    PathNotWriteable, // you tried to write to some filepath that wasn't writeable for some reason.
    InvalidBitcoinAddress, // you gave a receiving address to the OP_RETURN script generator that isn't a valid Bitcoin address.
    InvalidTag, // you provided an invalid tag to the OP_RETURN script generator.
    BalanceTooLow(f64), // can't generate a valid script because the balance is lower than the expected transaction fee.
    Internal(String), // for assorted internal problems
} 

impl std::fmt::Display for FailureReason {
    fn fmt (&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FailureReason::Success => write!(f, "The timestamp was successfully verified."),
            FailureReason::EmptyCorpus=> write!(f, "The provided directory has no timestampable files."),
            FailureReason::MerkleFileNotFound(s) => write!(f, "The provided merkle tree file path {s} could not be found."),
            FailureReason::MerkleFileNotParseable(s) => write!(f, "The file containing the merkle tree could not be parsed. The problem is on line {s} of the file."),
            FailureReason::MerkleTreeInconsistent => write!(f, "The provided merkle tree is inconsistent. Either the number of leaves is wrong, or the internal hashes don't line up."),
            FailureReason::LeafHashesFileNotFound(s) => write!(f, "The provided leaf hashes file path {s} could not be found."),
            FailureReason::ExplainFileNotParseable(s) => write!(f, "Explain.txt could not be parsed. The problem is on line {s} of the file."),
            FailureReason::ExplainFileNotFound(s) => write!(f, "Could not find explain file at location {s}."),
            FailureReason::ProofFileNotParseable(s) => write!(f, "The provided proof file could not be parsed. The problem is on line {s} of the file."),
            FailureReason::ProofFileNotFound(s) => write!(f, "The provided proof file path {s} could not be found."),
            FailureReason::ProofWrongLength(s,t) => write!(f, "The provided proof has length {s} but should have length {t}."),
            FailureReason::ExplainHashMismatch => write!(f, "The hash of explain.txt does not match the hash listed in the merkle/proof file header."),
            FailureReason::FileHashMismatch => write!(f, "The hash of the provided file does not match the expected hash in the proof file."),
            FailureReason::FileNotInMerkleTree => write!(f, "The provided file is not in the Merkle tree."),
            FailureReason::FileNotFound => write!(f, "The provided file could not be found."),
            FailureReason::FileReadError(s) => write!(f, "Error reading file at path {s}."),
            FailureReason::InvalidIdentifier => write!(f, "The provided identifier string must be exactly 8 ASCII characters, and no character may be a whitespace or control character."),
            FailureReason::TxHashNotParseable => write!(f, "The provided tx hash is invalid; it must contain only valid hex characters and be exactly 64 characters long."),
            FailureReason::NoBlockchainResponse => write!(f, "The blockchain lookup website did not respond to the request."),
            FailureReason::TxNotFound => write!(f, "The blockchain lookup website could not find a transaction with the specified tx hash."),
            FailureReason::TxUnconfirmed => write!(f, "The transaction has been submitted to the blockchain but hasn't been confirmed (mined) yet."),
            FailureReason::TimestampMismatchFatal => write!(f, "The utc timestamp listed in explain.txt is > 24hrs different than utc timestamp on the blockchain."),
            FailureReason::TagNotFound => write!(f, "The expected timestamp message was not found in the blockchain transaction."),
            FailureReason::UnexpectedBlockchainResponse => write!(f, "The blockchain response is malformed and the timestamp can't be verified. Try again."),
            FailureReason::PathNotWriteable => write!(f, "Couldn't write output file at the specified location."),
            FailureReason::InvalidBitcoinAddress => write!(f, "Receiving address isn't a valid Bitcoin address."),
            FailureReason::InvalidTag => write!(f, "Specified tag is invalid."),
            FailureReason::BalanceTooLow(s) => write!(f, "Can't generate script because the balance you entered is lower than the expected fee of {s}."),
            FailureReason::Internal(s) => write!(f, "Amber hit an internal error and could not finish. This is a bug, please report it. Details: {s}"),
        }
    }
}

pub enum Warning {
    AutoAccept, // a fake success. here you check the local parts of the timestamp match each other but don't actually look at the blockchain.
    TimestampMismatchNonFatal, // the tag was found in the transaction, but the tx timestamp doesn't match the one listed in the tree/proof file.
    // this is a success technically because the timestamp WAS found, but the time listed in the file header may be significantly wrong.
    BlockHeightMismatchNonFatal,
    MerkleTreeInconsistentNonfatal(usize), // e.g., internal merkle node from file doesn't match computed, but the root still matches.
}

impl std::fmt::Display for Warning {
    fn fmt (&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Warning::AutoAccept => write!(f, "The timestamp was locally verified, but not checked on the blockchain."),
            Warning::TimestampMismatchNonFatal => write!(f, "While the timestamp verified successfully on the blockchain, the utc timestamp listed in the merkle tree file header is wrong; It does not match the true timestamp on the blockchain. This header value should be corrected."),
            Warning::BlockHeightMismatchNonFatal => write!(f, "While the timestamp verified successfully on the blockchain, the block height in the fossil file does not match the true block height of the transaction containing the timestamp. This header value should be corrected."),
            Warning::MerkleTreeInconsistentNonfatal(s) => write!(f, "An internal node from the computed merkle tree doesn't match the merkle file, but the root hashes still match. The mismatch is node {s}."),
        }
    }
}

pub fn parse_hash(input_string: &str) -> Result<[u8; 32], FailureReason> {

    merkle::parse_hash_from_str(input_string)
}

pub fn get_locktime() -> Result<usize, FailureReason> {
    let block_height = verify::get_current_latest_block()?;
    Ok(block_height + 1)
}

pub fn build_timestamp_gui(corpus_name: String, identifier: String, hashes_source: bool, input_hashes_path: Option<PathBuf>, input_source_dir: Option<PathBuf>, corpus_desc: String, corpus_motiv: String, user_desc: String, timestamp_output_path: PathBuf) -> Result<(MerkleTree, usize, PathBuf, PathBuf, PathBuf, Vec<Warning>), FailureReason> {
    let locktime = get_locktime()?;

    let mut output_dir = timestamp_output_path;
    output_dir.push("merkle.txt");
    let tree_filename = output_dir.clone();
    output_dir.pop();

    output_dir.push("explain.txt");
    let explain_filename = output_dir.clone();
    output_dir.pop();

    output_dir.push("tag.txt");
    let tag_filename = output_dir.clone();
    output_dir.pop();

    output_dir.push("leaf_hashes.txt");
    let leaf_hash_filename = output_dir.clone();
    output_dir.pop();

    //let output_path = self.timestamp_output_path.as_ref().unwrap().to_str().unwrap();
    let mut corpus_path = &Default::default();
    let hashes_path;

    if hashes_source {
        hashes_path = input_hashes_path.as_ref().unwrap();
    }
    else {
        corpus_path = input_source_dir.as_ref().unwrap();
        hashes_path = &leaf_hash_filename;
    }

    let (tree, warnings) = build_timestamp(corpus_path, hashes_path, hashes_source, &tree_filename, &explain_filename, &tag_filename, &corpus_name, locktime, &identifier, Some(corpus_desc), Some(corpus_motiv), Some(user_desc))?;

    Ok((tree, locktime, tree_filename, explain_filename, tag_filename, warnings))
}

pub fn generate_op_return_script(receiving_address: &str, balance: f64, tag: &str) -> Result<(String, f64), FailureReason> {
    // make sure address is valid Bitcoin address
    let address_unchecked: Address<NetworkUnchecked> = match receiving_address.parse() {
        Ok(value) => value,
        Err(_) => return Err(FailureReason::InvalidBitcoinAddress),
    };
    let address: Address = match address_unchecked.require_network(Network::Bitcoin) {
        Ok(value) => value,
        Err(_) => return Err(FailureReason::InvalidBitcoinAddress),
    };
    //make sure tag is 76 bytes in hex form
    if !verify::tag_valid(tag) {
        return Err(FailureReason::InvalidTag)
    }

    verify::generate_op_return_script(&address.to_string(), balance, tag)
}

pub fn check_confirmations(tx_hash_string: &str) -> Result<usize, FailureReason> {
    // make sure it's a valid tx hash string
    let _ = parse_hash_from_string(tx_hash_string)?;
    verify::check_confirmations(tx_hash_string)
}