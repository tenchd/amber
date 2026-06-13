#[allow(dead_code)]
#[allow(unused_imports)]

mod merkle;
mod tag;
mod tests;

use hex_fmt::HexFmt;
use std::fs::File;
use std::io::{Write};
use config::Config;
use crate::merkle::MerkleTree;


// Scan current directory for files of the form "pg<number>", add them to a vector. All other files are ignored. This vector of file paths is used to build the merkle tree leaves.
// As per the specification for building the merkle tree from the PG text files, this list of file paths MUST be sorted in increasing order of PG index, because that is the order the leaves of the merkle tree should have.
// If you use a different order, the root hash of the merkle tree will be wrong.
fn get_filenames_from_directory(path: &str) -> Vec<String> {
    let mut filepaths: Vec<String> = std::fs::read_dir(path)
        .expect("Failed to read directory")
        .filter_map(|entry| {
            let entry = entry.expect("Failed to read directory entry");
            let filename = entry.file_name().into_string().expect("Failed to convert OsString to String");
            //if filename.starts_with("PG") && filename.ends_with("_raw.txt") {
            if filename.starts_with("pg") && filename.ends_with(".txt") {
                Some(entry.path().to_str().unwrap().to_string())
            } else {
                None 
            }
        })
        .collect();
    filepaths.sort_by(|a, b| {
        let a_num: usize = a.split("pg").nth(1).unwrap().split(".txt").nth(0).unwrap().parse().unwrap();
        let b_num: usize = b.split("pg").nth(1).unwrap().split(".txt").nth(0).unwrap().parse().unwrap();
        a_num.cmp(&b_num)
    });
    println!("Number of files: {}.", filepaths.len());
    println!("Last item in the set: {}", &filepaths.last().unwrap());
    filepaths
}

fn build_merkle_tree_from_directory(path: &str) -> MerkleTree {
    let filepaths = get_filenames_from_directory(path);
    MerkleTree::new_from_files(filepaths.iter().map(|s| s.as_str()).collect())
}
fn build_doc_and_tag_from_saved_tree(tree_filename: &str, date: &str, time: &str, block_lockout: usize, identifier: &str){
    println!("reading merkle tree from file.");
    let unfossilized: MerkleTree = MerkleTree::new_from_fossilized_tree(tree_filename);
    println!("Merkle tree has root hash: {}... and contains {} leaves", HexFmt(&unfossilized.get_root_hash()[..4]), unfossilized.num_leaves);
    unfossilized.verify_tree();
    println!("Merkle tree verified.");

    let document_filename = "timestamp/explain.txt";
    crate::tag::write_document(document_filename, date, time, block_lockout, identifier, unfossilized.num_leaves.try_into().unwrap(), unfossilized.get_root_hash());
    let tag = crate::tag::create_chain_tag(identifier, unfossilized.num_leaves.try_into().unwrap(), unfossilized.get_root_hash(), document_filename);
    println!("Wrote explainer document to file {}", document_filename);
    let tag_filename = "timestamp/tag.txt";
    let tag_string = format!("{}", HexFmt(&tag));
    let mut file = File::create(tag_filename).expect("failed to create file");
    file.write_all(&tag_string.into_bytes()).expect("failed to write tag");
    println!("Wrote tag to file {}", tag_filename);
}

fn build_timestamp(corpus_path: &str, tree_filename: &str, date: &str, time: &str, block_lockout: usize, identifier: &str) {
    let tree = build_merkle_tree_from_directory(corpus_path);
    tree.fossilize_tree(tree_filename, date);
    println!("wrote tree to file.");

    build_doc_and_tag_from_saved_tree(tree_filename, date, time, block_lockout, identifier);
}

fn main() {
    let settings = Config::builder()
                    .add_source(config::File::with_name("config"))
                    .build()
                    .unwrap();
    let corpus_path = settings.get_string("corpus_path").unwrap();
    let tree_filename = settings.get_string("tree_filename").unwrap();
    let date = settings.get_string("date").unwrap();
    let time = settings.get_string("time").unwrap();
    let block_lockout: usize = settings.get_string("block_lockout").unwrap().parse().expect("couldn't parse block lockout");
    let identifier = settings.get_string("identifier").unwrap();

    //get_filenames_from_directory(&corpus_path);

    //build_timestamp(&corpus_path, &tree_filename, &date, &time, block_lockout, &identifier);
    build_doc_and_tag_from_saved_tree(&tree_filename, &date, &time, block_lockout, &identifier);
}
