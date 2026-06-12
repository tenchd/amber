#![allow(dead_code)]
#![allow(unused_imports)]

mod merkle;
mod tag;
mod tests;

use hex_fmt::HexFmt;
//use sha2::digest::const_oid::ObjectIdentifier;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
//use serde_json::Result;
use std::{fmt, fs};
use std::fs::File;
use std::io::{Read,Write};
use std::collections::HashMap;
use config::Config;
use crate::merkle::MerkleTree;



fn get_filenames_from_directory(path: &str) -> Vec<String> {
    // scan current directory for files of the form "PG<number>_raw.txt", add them to a vector, and then build the tree from that vector of file paths.
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
    //println!("Building Merkle tree from files: {:?}", filepaths);
    println!("Number of files: {}.", filepaths.len());
    //println!("First ten files in the set: {:#?}", &filepaths[0..100]);
    println!("Last item in the set: {}", &filepaths.last().unwrap());
    filepaths
}

fn build_merkle_tree_from_directory(path: &str) -> MerkleTree {
    let filepaths = get_filenames_from_directory(path);
    MerkleTree::new_from_files(filepaths.iter().map(|s| s.as_str()).collect())
}
fn build_doc_and_tag_from_saved_tree(tree_filename: &str){
    println!("reading merkle tree from file.");
    let json_data = fs::read_to_string(tree_filename).expect("failed to read file");
    let deserialized: MerkleTree = serde_json::from_str(&json_data).unwrap();
    println!("Merkle tree has root hash: {:x?}... and contains {} leaves", HexFmt(&deserialized.get_root_hash()[..4]), deserialized.num_leaves);
    deserialized.verify_tree();
    println!("Merkle tree verified.");

    let document_filename = "timestamp/explain.txt";
    let identifier = "PGMERKLE";
    crate::tag::write_document(document_filename, "June 11, 2026", "13:50", 953259, identifier, deserialized.num_leaves.try_into().unwrap(), deserialized.get_root_hash());
    let tag = crate::tag::create_chain_tag(identifier, deserialized.num_leaves.try_into().unwrap(), deserialized.get_root_hash(), document_filename);
    println!("Wrote explainer document to file {}", document_filename);
    //println!("Tag is {}", hex_fmt::HexFmt(&tag));
    let tag_filename = "timestamp/tag.txt";
    let tag_string = format!("{}", HexFmt(&tag));
    let mut file = File::create(tag_filename).expect("failed to create file");
    file.write_all(&tag_string.into_bytes()).expect("failed to write tag");
    println!("Wrote tag to file {}", tag_filename);
}

fn build_timestamp(corpus_path: &str) {
    let tree = build_merkle_tree_from_directory(corpus_path);
    let tree_filename = "timestamp/pgtree.json";
    let serialized = serde_json::to_string(&tree).unwrap();
    let mut file = File::create(tree_filename).expect("failed to create file");
    file.write_all(serialized.as_bytes()).expect("failed to write data");
    println!("wrote tree to file.");

    build_doc_and_tag_from_saved_tree(tree_filename);
}

fn main() {
    let settings = Config::builder()
                    .add_source(config::File::with_name("config"))
                    .build()
                    .unwrap();
    let corpus_path = settings.get_string("corpus_path").unwrap();
    let tree_filename = "timestamp/pgtree.json";

    //get_filenames_from_directory(&corpus_path);
    //build_timestamp(&corpus_path);
    build_doc_and_tag_from_saved_tree(tree_filename);
}
