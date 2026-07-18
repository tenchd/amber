mod merkle;
mod tag;
mod tests;
mod verify;

use hex_fmt::HexFmt;
use std::fs::File;
use std::io::{Write};
use config::Config;
use clap::Parser;
use walkdir::WalkDir;
use crate::merkle::{double_hash_from_file, parse_hash_from_str};
use crate::{
    merkle::{MerkleProof, MerkleTree, TimestampedMerkleTree}
};

const AMBER_VERSION: usize = 1;
const AMBER_VERSION_DATE: &str = "August 24, 2026";

// command line parsing
#[derive(Parser, Debug)]
#[command(version, about, long_about = Option::None)]
struct Args {
    #[arg(short, long, default_value_t = false)]
    build_tree_and_doc: bool,

    #[arg(short, long, default_value_t = false)]
    generate_timestamp: bool,

    #[arg(short, long, default_value_t = false)]
    verify_timestamp: bool,

    #[arg(short, long, default_value_t = ("".to_string()))]
    file_to_verify: String,

    #[arg(short, long, default_value_t = ("".to_string()))]
    proof_verify: String,
}

// Scans corpus top-level directory recursively to gather the files that will be put in the merkle tree.
fn get_filenames_from_directory(path: &str) -> Vec<String> {
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
    println!("Building a Merkle tree from {} files. This may take a couple of minutes.", filepaths.len());
    filepaths
}

fn build_merkle_tree_from_directory(path: &str) -> MerkleTree {
    let filepaths = get_filenames_from_directory(path);
    //println!("{}", filepaths.first().unwrap());
    MerkleTree::new_from_files(filepaths.iter().map(|s| s.as_str()).collect())
}
fn build_doc_and_tag_from_saved_tree(tree_filename: &str, corpus_name: &str, date: &str, time: &str, locktime: usize, identifier: &str){
    println!("reading merkle tree from file.");
    let unfossilized: MerkleTree = MerkleTree::new_from_unfinished_tree_file(tree_filename);
    println!("Merkle tree has root hash: {}... and contains {} leaves", HexFmt(&unfossilized.get_root_hash()[..4]), unfossilized.num_leaves);
    unfossilized.verify_tree();
    println!("Merkle tree is valid.");

    let document_filename = "generated_timestamp/explain.txt";
    crate::tag::write_document(document_filename, corpus_name, date, time, locktime, identifier, unfossilized.num_leaves.try_into().unwrap(), unfossilized.get_root_hash());
    let document_hash = double_hash_from_file(document_filename);
    let tag = crate::tag::create_chain_tag(identifier, unfossilized.num_leaves.try_into().unwrap(), unfossilized.get_root_hash(), document_hash);
    println!("Wrote explainer document to file {}", document_filename);
    let tag_filename = "generated_timestamp/tag.txt";
    let tag_string = format!("{}", HexFmt(&tag));
    let mut file = File::create(tag_filename).expect("failed to create file");
    file.write_all(&tag_string.into_bytes()).expect("failed to write tag");
    println!("Wrote tag to file {}", tag_filename);
}

fn build_timestamp(corpus_path: &str, tree_filename: &str, corpus_name: &str, date: &str, time: &str, locktime: usize, identifier: &str) {
    let tree = build_merkle_tree_from_directory(corpus_path);
    let tree_filename_unfinished = format!("{}_unfinished.txt",tree_filename);
    println!("Merkle tree built. Root hash is {}", HexFmt(tree.get_root_hash()));
    tree.write_unfinished_tree_to_file(&tree_filename_unfinished, date);
    println!("wrote tree to file {}", tree_filename_unfinished);

    build_doc_and_tag_from_saved_tree(&tree_filename_unfinished, corpus_name, date, time, locktime, identifier);
}

fn finalize_timestamp(generated_tree_filename: &str, generated_explain_filename: &str, identifier: &str, block_height: usize, tx_hash: [u8; 32], date: &str) {
    let unfinished_tree_file = format!("{}_unfinished.txt",generated_tree_filename);
    let unfinished_tree = MerkleTree::new_from_unfinished_tree_file(&unfinished_tree_file);
    let explain_hash = double_hash_from_file(generated_explain_filename);
    let mut timestamped_tree = TimestampedMerkleTree::new(unfinished_tree, &identifier, block_height, tx_hash, explain_hash);
    println!("verifying tree file at {}", unfinished_tree_file);
    let autoaccept = true;
    let result = timestamped_tree.verify_timestamp(generated_explain_filename, autoaccept);
    if result {
        timestamped_tree.fossilize_tree(generated_tree_filename, &date);

        println!("Timestamp verified! Wrote the updated merkle tree file at {}. Deleting temporary untimestamped merkle tree file at {}", generated_tree_filename, unfinished_tree_file);
        std::fs::remove_file(unfinished_tree_file).unwrap();
    }
    if autoaccept{
        println!("WARNING: you set the autoaccept flag to true so we did not actually verify w.r.t. the blockchain. This was for testing purposes only.");
    }
}

fn verify_file(tree_filename: &str, filepath: &str){
    println!("reading merkle tree from file.");
    let unfossilized: MerkleTree = MerkleTree::new_from_unfinished_tree_file(tree_filename);
    println!("Merkle tree has root hash: {}... and contains {} leaves", HexFmt(&unfossilized.get_root_hash()[..4]), unfossilized.num_leaves);
    unfossilized.verify_tree();
    println!("Merkle tree is valid.");

    let contains = unfossilized.verify_from_file(filepath);
    if contains {
        println!("{} is in the Merkle tree.", filepath);
    }
    else {
        println!("{} is NOT in the Merkle tree.", filepath);
    }
}

fn verify_proof(filepath: &str, proof_file: &str) {
    let proof = MerkleProof::new_from_file(proof_file);
    let result = proof.verify_proof_for_file(filepath, false);
    if result {
        println!("File {} was verified by proof file {} for root hash {}.", filepath, proof_file, HexFmt(proof.root_hash));
    }
    else {
        println!("File {} failed to verify for proof file {}. It does NOT certify any timestamp for the file.", filepath, proof_file);
    }
}

fn main() {
    let settings = Config::builder()
                    .add_source(config::File::with_name("config"))
                    .build()
                    .unwrap();
    let corpus_path = settings.get_string("corpus_path").unwrap();
    let generated_tree_filename = "generated_timestamp/merkle.txt";
    let generated_explain_filename = "generated_timestamp/explain.txt";
    let provided_tree_filename = settings.get_string("provided_tree_path").unwrap();
    let provided_explain_filename = settings.get_string("provided_explain_path").unwrap();
    let date = settings.get_string("date").unwrap();
    let time = settings.get_string("time").unwrap();
    let locktime: usize = settings.get_string("locktime").unwrap().parse().expect("couldn't parse block lockout");
    let identifier = settings.get_string("identifier").unwrap();

    let args = Args::parse();

    if args.build_tree_and_doc {
        if args.file_to_verify != "".to_string() {
            println!("Ignoring verification request. Building tree+docs.")
        }
        let corpus_name = settings.get_string("corpus_name").unwrap();
        build_timestamp(&corpus_path, &generated_tree_filename, &corpus_name, &date, &time, locktime, &identifier);

    }
    else if args.generate_timestamp {
        if args.file_to_verify != "".to_string() {
            println!("Ignoring verification request. Building timestamp.");
        }
        let block_height: usize = settings.get_string("block_height").unwrap().parse().unwrap();
        let tx_hash_string = settings.get_string("tx_hash").unwrap();
        let tx_hash = parse_hash_from_str(&tx_hash_string);
        // need to read in unfinished merkle file, build a timestamped merkle file from it, verify the timestamp on the chain, then write to the timestamped tree to file.
        finalize_timestamp(generated_tree_filename, generated_explain_filename, &identifier, block_height, tx_hash, &date);

    }
    else if args.verify_timestamp {
        println!("Verifying timestamp in {}", provided_tree_filename);
        let mut timestamped_tree = TimestampedMerkleTree::new_from_fossilized_tree(&provided_tree_filename);
        let autoaccept = false;
        let result = timestamped_tree.verify_timestamp(&provided_explain_filename, autoaccept);
        if !result {
            println!("failed to verify");
        }
    }
    else if args.file_to_verify != "".to_string() {
        let filepath = args.file_to_verify;
        if args.proof_verify != "".to_string() {
            let proof_file = args.proof_verify;
            verify_proof(&filepath, &proof_file);
        }
        else {
            verify_file(&provided_tree_filename, &filepath);
        }
    }
    else {
        panic!("Need to provide a command line argument");
    }

}
