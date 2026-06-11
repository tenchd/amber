mod tests;
mod tag;

use sha2::digest::const_oid::ObjectIdentifier;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use serde_json::Result;
use std::{fmt, fs};
use std::fs::File;
use std::io::{Read};

//fn double_hash(input: &[u8]) -> Array<u8, <Sha256 as OutputSizeUser>::OutputSize> {
fn double_hash(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let first_hash = hasher.finalize_reset();
    hasher.update(&first_hash);
    let result = hasher.finalize();
    let mut hash_bytes = vec![0u8; 32];
    hash_bytes.copy_from_slice(&result);
    let hash_bytes_length: [u8; 32] = hash_bytes.try_into().expect("Hash length must be 32 bytes");
    hash_bytes_length
}

fn double_hash_from_file(filepath: &str) -> [u8; 32] {
    let mut file = File::open(filepath).expect("Failed to open file");
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024]; // Process in 1KB chunks

    loop {
            let bytes_read = file.read(&mut buffer).expect("Failed to read file");
            if bytes_read == 0 {
                break; // Reached end of file
            }
            hasher.update(&buffer[..bytes_read]);
        }

    let first_hash = hasher.finalize_reset();
    hasher.update(&first_hash);
    let result = hasher.finalize();
    let mut hash_bytes = vec![0u8; 32];
    hash_bytes.copy_from_slice(&result);
    let hash_bytes_length: [u8; 32] = hash_bytes.try_into().expect("Hash length must be 32 bytes");
    hash_bytes_length
}

// nodes are owned by the 'nodes' vector in the MerkleTree struct. 0 means none.
type NodeHandle = usize;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MerkleNode {
    hash: [u8; 32],
    index: NodeHandle,
    left: NodeHandle,
    right: NodeHandle,
    parent: NodeHandle,
}

impl MerkleNode {
    fn new_leaf(hash: [u8; 32], index: usize) -> Self {
        MerkleNode { hash, index, left: 0, right: 0, parent: 0 }
    }

    fn new_leaf_from_file(filepath: &str, index: usize) -> Self {
        let hash = double_hash_from_file(filepath);
        MerkleNode { hash, index, left: 0, right: 0, parent: 0 }
    }

    fn new_internal(left: &mut MerkleNode, right: &mut MerkleNode, index: usize) -> Self {
        //println!("Creating internal node {} with left child {} and right child {}", index, left.index, right.index);
        let hash = double_hash(&[left.hash, right.hash].concat());
        let new_node = MerkleNode { hash, index, left: left.index, right: right.index, parent: 0 };
        left.parent = index;
        right.parent = index;
        new_node
    }

    fn new_internal_end(left: &mut MerkleNode, index: usize) -> Self {
        //println!("Creating internal node {} with left child {} and no right child", index, left.index);
        let hash = double_hash(&[left.hash, left.hash].concat());
        let new_node = MerkleNode { hash, index, left: left.index, right: 0, parent: 0 };
        left.parent = index;
        new_node
    }
}

impl fmt::Display for MerkleNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MerkleNode {{ hash prefix: {:x?}, index: {}, left: {}, right: {}, parent: {} }}", &self.hash[..4], self.index, self.left, self.right, self.parent)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct MerkleProof {
    leaf_index: usize,
    proof_hashes: Vec<[u8; 32]>,
    proof_directions: Vec<bool>, // true for left, false for right
}
impl fmt::Display for MerkleProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MerkleProof for leaf_index {}:", self.leaf_index)?;
        for (i, hash) in self.proof_hashes.iter().enumerate() {
            let direction = if self.proof_directions[i] { "left" } else { "right" };
            write!(f, "\n  {} sibling hash: {:x?}", direction, &hash[..4])?;
        }      
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct MerkleTree {
    root_index: usize,
    num_leaves: usize,
    nodes: Vec<MerkleNode>,
}

#[allow(dead_code)]
impl MerkleTree {
    fn new_from_data(data: Vec<&[u8]>) -> Self {
        let num_leaves = data.len();
        let mut nodes: Vec<MerkleNode> = vec![];
        nodes.push(MerkleNode { hash: [0u8; 32], index: 0, left: 0, right: 0, parent: 0 }); // dummy node at index 0
        for (index, d) in data.iter().enumerate() {
            nodes.push(MerkleNode::new_leaf(double_hash(d).into(), index + 1));
        }
        let root_index = MerkleTree::build_tree(&mut nodes, num_leaves, false);
        MerkleTree { root_index, num_leaves, nodes }
    }

    // Assumes files are all in a single directory and have names of the form "PG<number>_raw.txt". All other files are ignored. The order of the files in the tree is determined by the number in the filename, with smaller numbers coming first. For example, "PG1_raw.txt" would be the first leaf, "PG2_raw.txt" would be the second leaf, and so on.
    fn new_from_files(filepaths: Vec<&str>) -> Self {
        let num_leaves = filepaths.len();
        let mut nodes: Vec<MerkleNode> = vec![];
        nodes.push(MerkleNode { hash: [0u8; 32], index: 0, left: 0, right: 0, parent: 0 }); // dummy node at index 0
        for (index, filepath) in filepaths.iter().enumerate() {
            nodes.push(MerkleNode::new_leaf_from_file(filepath, index + 1));
        }
        let root_index = MerkleTree::build_tree(&mut nodes, num_leaves, false);
        MerkleTree { root_index, num_leaves, nodes }
    }

    fn display_state(nodes: &Vec<MerkleNode>) {
        println!("---Merkle Tree State:----");
        for node in nodes {
            println!("{}", node);
        }
        println!("-------------------------");
    }

    fn build_tree(nodes: &mut Vec<MerkleNode>, num_leaves: usize, debug: bool) -> usize {
        let mut current_level_start = 1;
        let mut next_level_start: usize = num_leaves + 1;
        let mut current_pointer = num_leaves + 1;

        while current_level_start + 1 < next_level_start {
            if debug {
                println!("working from index {} to {}", current_level_start, next_level_start);
            }
            for i in (current_level_start..next_level_start).step_by(2) {
                if debug {
                    println!("current index i = {}, current write pointer = {}", i, current_pointer);
                }
                if i + 1 < next_level_start {
                    if debug {
                        println!("inner case");
                    }
                    let (left_side, right_side) = nodes.split_at_mut(i + 1);
                    //println!("splitting at index {} into left {:#?} and right {:#?}", i, left_side, right_side);
                    let mut left = &mut left_side[i];
                    let mut right = &mut right_side[0];
                    let parent = MerkleNode::new_internal(&mut left, &mut right, current_pointer);
                    nodes.push(parent);
                    if debug {
                        MerkleTree::display_state(nodes);
                    }
                }
                else {
                    if debug {
                        println!("end case");
                    }
                    let mut left = &mut nodes[i];
                    //println!("selected node {}: {}", i, left);
                    let parent = MerkleNode::new_internal_end(&mut left, current_pointer);
                    nodes.push(parent);
                    if debug {
                        MerkleTree::display_state(nodes);
                    }
                }
                current_pointer += 1;
            }
            current_level_start = next_level_start;
            next_level_start = current_pointer;
        }

        nodes.len() - 1
    }

    fn get_root_hash(&self) -> [u8; 32] {
        self.nodes[self.root_index].hash
    }

    fn is_a_leaf(&self, node: &MerkleNode) -> bool {
        node.index < self.num_leaves + 1 && node.index != 0
    }

    fn matches_hash(&self, node: &MerkleNode, data: &[u8]) -> bool {
        let leaf_hash = double_hash(data);
        node.hash == leaf_hash
    }

    fn matches_hash_from_file(&self, node: &MerkleNode, filepath: &str) -> bool {
        let leaf_hash = double_hash_from_file(filepath);
        node.hash == leaf_hash
    }

    fn verify_with_index(&self, data: &[u8], index: usize) -> bool {
        self.is_a_leaf(&self.nodes[index]) && self.matches_hash(&self.nodes[index], data)
    }

    fn verify_with_index_from_file(&self, filepath: &str, index: usize) -> bool {
        self.is_a_leaf(&self.nodes[index]) && self.matches_hash_from_file(&self.nodes[index], filepath)
    }

    fn verify_without_index(&self, data: &[u8]) -> bool {
        self.nodes.iter().any(|node| self.is_a_leaf(node) && self.matches_hash(node, data))
    }

    fn verify_without_index_from_file(&self, filepath: &str) -> bool {
        self.nodes.iter().any(|node| self.is_a_leaf(node) && self.matches_hash_from_file(node, filepath))
    }

    fn produce_proof(&self, index: usize) -> MerkleProof {
        let mut proof_hashes = Vec::new();
        let mut proof_directions = Vec::new();
        let mut current_index = index;
        while current_index != self.root_index {
            //println!("Current index: {}, hash: {:x?}", current_index, &self.nodes[current_index].hash[..4]);
            let parent_index = self.nodes[current_index].parent;
            let sibling_index = if self.nodes[parent_index].left == current_index {
                self.nodes[parent_index].right
            } else {
                self.nodes[parent_index].left
            };
            if sibling_index == 0 {
                proof_hashes.push(self.nodes[current_index].hash);
            }
            else {
                proof_hashes.push(self.nodes[sibling_index].hash);
            }
            proof_directions.push(self.nodes[parent_index].left == current_index);
            current_index = parent_index;
        }
        MerkleProof { leaf_index: index, proof_hashes, proof_directions }
    }

    fn verify_proof(&self, data: &[u8], proof: &MerkleProof) -> bool {
        let mut computed_hash = double_hash(data);
        for (i, sibling_hash) in proof.proof_hashes.iter().enumerate() {
            if proof.proof_directions[i] {
                computed_hash = double_hash(&[computed_hash, *sibling_hash].concat());
            } else {
                computed_hash = double_hash(&[*sibling_hash, computed_hash].concat());
            }
        }
        computed_hash == self.get_root_hash()
    }

    fn verify_proof_from_file(&self, filepath: &str, proof: &MerkleProof) -> bool {
        let mut computed_hash = double_hash_from_file(filepath);
        for (i, sibling_hash) in proof.proof_hashes.iter().enumerate() {
            if proof.proof_directions[i] {
                computed_hash = double_hash(&[computed_hash, *sibling_hash].concat());
            } else {
                computed_hash = double_hash(&[*sibling_hash, computed_hash].concat());
            }
        }
        computed_hash == self.get_root_hash()
    }

    fn verify_tree(&self) {
        for node in self.nodes.iter() {
            if self.is_a_leaf(&node) || node.index == 0 {
                continue;
            }

            assert!(node.left != 0);
            let left_index = &self.nodes[node.left];
            let left_hash = left_index.hash;
            if node.right > 0 {
                let right_index = &self.nodes[node.right];
                let right_hash = right_index.hash;
                let computed_hash = double_hash(&[left_hash, right_hash].concat());
                assert!(node.hash == computed_hash, 
                    "Merkle tree verification failed.\n 
                    Node {}'s hash does not match the double SHA256 hash of the concatenation of its children's hashes.\n
                    Left child has index {} and hash {:x?}.\n
                    Right child has index {} and hash {:x?}.\n
                    The double SHA256 hash of their concatenated hashes is {:x?}, but parent node {}'s hash is {:x?}.",
                node.index, left_index, left_hash, right_index, right_hash,computed_hash, node.index, node.hash);
            }
            else {
                let computed_hash = double_hash(&[left_hash, left_hash].concat());
                assert!(node.hash == computed_hash, 
                    "Merkle tree verification failed.\n
                    Node {}'s hash does not match the double SHA256 hash of the self-concatenation of its child's hash.\n
                    Left (only) child has index {} and hash {:x?}.\n
                    Concatenating it with itself and double SHA256 hashing is {:x?}, but parent node {}'s hash is {:x?}.",
                    node.index, left_index, left_hash, computed_hash, node.index, node.hash);
            }
        }
    }
}

fn build_merkle_tree_from_directory(path: &str) -> MerkleTree {
    // scan current directory for files of the form "PG<number>_raw.txt", add them to a vector, and then build the tree from that vector of file paths.
    let mut filepaths: Vec<String> = std::fs::read_dir(path)
        .expect("Failed to read directory")
        .filter_map(|entry| {
            let entry = entry.expect("Failed to read directory entry");
            let filename = entry.file_name().into_string().expect("Failed to convert OsString to String");
            if filename.starts_with("PG") && filename.ends_with("_raw.txt") {
                Some(entry.path().to_str().unwrap().to_string())
            } else {
                None 
            }
        })
        .collect();
    filepaths.sort_by(|a, b| {
        let a_num: usize = a.split("PG").nth(1).unwrap().split("_").nth(0).unwrap().parse().unwrap();
        let b_num: usize = b.split("PG").nth(1).unwrap().split("_").nth(0).unwrap().parse().unwrap();
        a_num.cmp(&b_num)
    });
    //println!("Building Merkle tree from files: {:?}", filepaths);
    println!("Number of files: {}. Should be 78706", filepaths.len());
    MerkleTree::new_from_files(filepaths.iter().map(|s| s.as_str()).collect())
}

fn main() {
    // let path = "../small_merkel";
    // let path = "../gutenberg/data/raw/";
    // let merkle_tree = build_merkle_tree_from_directory(path);
    // println!("Merkle tree built from directory {} has root hash: {:x?}... and contains {} leaves", path, &merkle_tree.get_root_hash()[..4], merkle_tree.num_leaves);
    // let serialized = serde_json::to_string(&merkle_tree).unwrap();
    let tree_filename = "pgtree.json";
    // let mut file = File::create(tree_filename).expect("filed to create file");
    // file.write_all(serialized.as_bytes()).expect("failed to write data");
    // println!("wrote tree to file.");

    println!("reading tree from file:");
    let json_data = fs::read_to_string(tree_filename).expect("failed to read file");
    let deserialized: MerkleTree = serde_json::from_str(&json_data).unwrap();
    println!("Deserialized Merkle tree has root hash: {:x?}... and contains {} leaves", &deserialized.get_root_hash()[..4], deserialized.num_leaves);
    deserialized.verify_tree();
    println!("Deserialized tree verified.");

    let document_filename = "explain_example.txt";
    let identifier = "PGMERKLE";
    crate::tag::write_document(document_filename, "June 10, 2026", "2:30", 953058, identifier, deserialized.num_leaves.try_into().unwrap(), deserialized.get_root_hash());
    let tag = crate::tag::create_chain_tag(identifier, deserialized.num_leaves.try_into().unwrap(), deserialized.get_root_hash(), document_filename);
    println!("Tag is {:x?}", hex_fmt::HexFmt(tag));
}
