mod merkle;
mod tag;
mod tests;

use hex_fmt::HexFmt;
use std::fs::File;
use std::io::{Write};
use config::Config;
use clap::Parser;
use walkdir::WalkDir;
use crate::merkle::MerkleTree;

// command line parsing
#[derive(Parser, Debug)]
#[command(version, about, long_about = Option::None)]
struct Args {
    #[arg(short, long, default_value_t = false)]
    build_tree: bool,

    // #[arg(short, long, default_value_t = false)]
    // tag: bool,

    // #[arg(short, long, default_value_t = false)]
    // generate_timestamp: bool,

    #[arg(short, long, default_value_t = ("".to_string()))]
    verify_file: String,
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
    println!("{}", filepaths.first().unwrap());
    MerkleTree::new_from_files(filepaths.iter().map(|s| s.as_str()).collect())
}
fn build_doc_and_tag_from_saved_tree(tree_filename: &str, date: &str, time: &str, locktime: usize, identifier: &str){
    println!("reading merkle tree from file.");
    let unfossilized: MerkleTree = MerkleTree::new_from_fossilized_tree(tree_filename);
    println!("Merkle tree has root hash: {}... and contains {} leaves", HexFmt(&unfossilized.get_root_hash()[..4]), unfossilized.num_leaves);
    unfossilized.verify_tree();
    println!("Merkle tree is valid.");

    let document_filename = "generated_timestamp/explain.txt";
    crate::tag::write_document(document_filename, date, time, locktime, identifier, unfossilized.num_leaves.try_into().unwrap(), unfossilized.get_root_hash());
    let tag = crate::tag::create_chain_tag(identifier, unfossilized.num_leaves.try_into().unwrap(), unfossilized.get_root_hash(), document_filename);
    println!("Wrote explainer document to file {}", document_filename);
    let tag_filename = "generated_timestamp/tag.txt";
    let tag_string = format!("{}", HexFmt(&tag));
    let mut file = File::create(tag_filename).expect("failed to create file");
    file.write_all(&tag_string.into_bytes()).expect("failed to write tag");
    println!("Wrote tag to file {}", tag_filename);
}

fn build_timestamp(corpus_path: &str, tree_filename: &str, date: &str, time: &str, locktime: usize, identifier: &str) {
    let tree = build_merkle_tree_from_directory(corpus_path);
    println!("Merkle tree built. Root hash is {}", HexFmt(tree.get_root_hash()));
    tree.fossilize_tree(tree_filename, date);
    println!("wrote tree to file {}", tree_filename);

    build_doc_and_tag_from_saved_tree(tree_filename, date, time, locktime, identifier);
}

fn verify_file(tree_filename: &str, filepath: &str){
    println!("reading merkle tree from file.");
    let unfossilized: MerkleTree = MerkleTree::new_from_fossilized_tree(tree_filename);
    println!("Merkle tree has root hash: {}... and contains {} leaves", HexFmt(&unfossilized.get_root_hash()[..4]), unfossilized.num_leaves);
    unfossilized.verify_tree();
    println!("Merkle tree is valid.");

    let contains = unfossilized.verify_without_index_from_file(filepath);
    if contains {
        println!("{} is in the Merkle tree.", filepath);
    }
    else {
        println!("{} is NOT in the Merkle tree.", filepath);
    }
}

fn compute_tag(identifier: &str, tree_filename: &str, explain_filepath: &str) {
    println!("reading merkle tree from file.");
    let unfossilized: MerkleTree = MerkleTree::new_from_fossilized_tree(tree_filename);
    println!("Merkle tree has root hash: {}... and contains {} leaves", HexFmt(&unfossilized.get_root_hash()[..4]), unfossilized.num_leaves);
    unfossilized.verify_tree();
    println!("Merkle tree is valid.");

    let num_leaves = unfossilized.num_leaves.try_into().unwrap();
    let root_hash = unfossilized.get_root_hash();
    let tag = tag::create_chain_tag(identifier, num_leaves, root_hash, explain_filepath);
    let opcodes = "6a4c4c"; //hex of opcodes used to write to bitcoin blockchain via OP_RETURN
    println!("Blockchain message should be\n{}{}", opcodes, HexFmt(tag));
}

fn main() {
    let settings = Config::builder()
                    .add_source(config::File::with_name("config"))
                    .build()
                    .unwrap();
    let corpus_path = settings.get_string("corpus_path").unwrap();
    let generated_tree_filename = "generated_timestamp/merkle.txt";
    let date = settings.get_string("date").unwrap();
    let time = settings.get_string("time").unwrap();
    let locktime: usize = settings.get_string("locktime").unwrap().parse().expect("couldn't parse block lockout");
    let identifier = settings.get_string("identifier").unwrap();

    let args = Args::parse();

    if args.verify_file != "".to_string(){
        let filepath = args.verify_file;
        let provided_tree_filename = settings.get_string("provided_tree_path").unwrap();
        verify_file(&provided_tree_filename, &filepath);
    }
    // else if args.tag {
    //     let explain_filepath = "canonical_timestamp/canonical_explain.txt";
    //     compute_tag(&identifier, &canonical_tree_filename, &explain_filepath);
    // }
    // else if args.generate_timestamp {
    //     build_doc_and_tag_from_saved_tree(&canonical_tree_filename, &date, &time, locktime, &identifier);
    // }
    else if args.build_tree {
        build_timestamp(&corpus_path, &generated_tree_filename, &date, &time, locktime, &identifier);
    }
    else {
        panic!("Need to provide a command line argument");
    }

}
