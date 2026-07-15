use hex_fmt::HexFmt;
use sha2::{Sha256, Digest};
use std::{fmt};
use std::fs::File;
use std::io::{Read,Write,BufReader, prelude::*,};
use std::collections::HashMap;
use base64::prelude::*;

// apply SHA256 hash twice to input bytes.
pub fn double_hash(input: &[u8]) -> [u8; 32] {
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

// apply SHA256 hash twice to file contents.
pub fn double_hash_from_file(filepath: &str) -> [u8; 32] {
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

// nodes are owned by the 'nodes' vector in the MerkleTree struct. a NodeHandle is a indentifier/index for a merkle node in the vector. 1-indexed; 0 means none.
type NodeHandle = usize;

// represents a single node in the merkle tree. Contains a hash, an index, and pointers to parent and children.
#[derive(Debug)]
pub struct MerkleNode {
    pub hash: [u8; 32],
    pub index: NodeHandle,
    left: NodeHandle,
    right: NodeHandle,
    parent: NodeHandle,
}

impl MerkleNode {
    // create a new leaf node from a provided hash.
    fn new_leaf(hash: [u8; 32], index: usize) -> Self {
        MerkleNode { hash, index, left: 0, right: 0, parent: 0 }
    }

    // create a new leaf node from a file.
    fn new_leaf_from_file(filepath: &str, index: usize) -> Self {
        let hash = double_hash_from_file(filepath);
        MerkleNode { hash, index, left: 0, right: 0, parent: 0 }
    }

    // create a new internal (non-leaf) node by concatenating child hashes and then double hashing.
    fn new_internal(left: &mut MerkleNode, right: &mut MerkleNode, index: usize) -> Self {
        let hash = double_hash(&[left.hash, right.hash].concat());
        let new_node = MerkleNode { hash, index, left: left.index, right: right.index, parent: 0 };
        left.parent = index;
        right.parent = index;
        new_node
    }

    // create a new internal (non-leaf) node with only one child.
    fn new_internal_end(left: &mut MerkleNode, index: usize) -> Self {
        let hash = double_hash(&[left.hash, left.hash].concat());
        let new_node = MerkleNode { hash, index, left: left.index, right: 0, parent: 0 };
        left.parent = index;
        new_node
    }
}

// Display pretty-prints only the first 4 bytes of node hash, to be more human-readable.
impl fmt::Display for MerkleNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MerkleNode {{ hash prefix: {:x?}, index: {}, left: {}, right: {}, parent: {} }}", &self.hash[..4], self.index, self.left, self.right, self.parent)
    }
}

// A Merkle proof for a file is the set of hashes you need to apply to the file to reach the root. Constructed only from a MerkleTree object, so has no constructor of its own.
#[derive(Debug)]
pub struct MerkleProof {
    pub root_hash: [u8; 32],
    pub proof_hashes: Vec<[u8; 32]>,
    pub proof_directions: Vec<bool>, // true for left, false for right
}

#[allow(dead_code)]
impl MerkleProof {
    pub fn new_from_file(proof_filepath: &str) -> MerkleProof {
        let mut proof_hashes: Vec<[u8; 32]> = vec![];
        let mut proof_directions: Vec<bool> = vec![];

        let file = File::open(proof_filepath).expect("couldn't open proof file");
        let mut reader = BufReader::new(file);

        let mut header_lines: Vec<String> = vec!["".to_string(); 4];
        for i in 0..4 {
            reader.read_line(&mut header_lines[i]).expect("Failed to read line");
        }

        let mut root_hash_line: String = "".to_string();
        reader.read_line(&mut root_hash_line).expect("could not read root hash line");
        root_hash_line = root_hash_line.trim_end().to_string();
        let root_hash = BASE64_STANDARD.decode(root_hash_line).expect("Could not decode line");
        let root_hash_bytes: [u8; 32] = root_hash.try_into().unwrap();

        for line in reader.lines() {
            let clean_line = line.expect("could not read line");
            let parts: Vec<&str> = clean_line.split(',').collect();
            assert!(parts.len() == 2, "proof line does not have two parts separated by comma");
            let fossil_hash = BASE64_STANDARD.decode(parts[0]).expect("Could not decode line");
            assert!(fossil_hash.len() == 32, "fossil hash is incorrect length");
            proof_hashes.push(fossil_hash.try_into().expect("Could not convert to bytes"));
            let direction = parts[1].trim().parse::<bool>().expect("Could not parse direction as boolean");
            proof_directions.push(direction);
        }

        MerkleProof { root_hash: root_hash_bytes, proof_hashes, proof_directions }
    }

    // 
    pub fn fossilize_proof(&self, filename: &str) {
        let mut file = File::create(filename).expect("failed to create file");
        let header_line = format!("# Merkle proof. The first uncommented line is the root hash. Each subsequent line is a hash in base64 followed by a boolean (separated by a comma).\n");
        let header_line2 = format!("# Each non-root line represents a step in the leaf-to-root Merkle proof path: the hash of the sibling node and the boolean indicates whether the sibling is the left (true) or right (false) sibling.\n");
        let header_line3 = format!("# To verify the proof, double SHA256 hash the file. Then for each line in the proof, concatenate the current hash with the sibling hash on the left (if true) or on the right (if false) and double SHA256 hash the concatenation. The end result should match the root hash.\n");
        let header_line4 = format!("# Locate the root hash on the blockchain to prove that the file existed at the time of the blockchain transaction that contains it.\n");

        file.write_all(header_line.as_bytes()).unwrap();
        file.write_all(header_line2.as_bytes()).unwrap();
        file.write_all(header_line3.as_bytes()).unwrap();
        file.write_all(header_line4.as_bytes()).unwrap();

        let root_hash_line = format!("{}\n", BASE64_STANDARD.encode(self.root_hash));
        file.write_all(root_hash_line.as_bytes()).unwrap();

        for i in 0..self.proof_hashes.len() {
            let line = format!("{},{}\n", BASE64_STANDARD.encode(self.proof_hashes[i]), self.proof_directions[i]);
            file.write_all(line.as_bytes()).unwrap();
        }
    }

    // verifies a proof starting from the leaf hash, proceeding along the leaf-to-root path encoded by the proof until the root hash is reached. If the proof is valid, this computed root hash will match the Merkle tree root hash.
    pub fn verify_proof(&self, starting_hash: [u8; 32]) -> bool {
        let mut computed_hash = starting_hash;
        for (i, sibling_hash) in self.proof_hashes.iter().enumerate() {
            if self.proof_directions[i] {
                computed_hash = double_hash(&[computed_hash, *sibling_hash].concat());
            } else {
                computed_hash = double_hash(&[*sibling_hash, computed_hash].concat());
            }
        }
        computed_hash == self.root_hash
    }

    // verifies that some data is part of a merkle tree (represented by its root hash).
    pub fn verify_proof_for_data(&self, data: &[u8]) -> bool {
        let starting_hash = double_hash(data);
        self.verify_proof(starting_hash)
    }

    // verifies that some file is part of a merkle tree (represented by its root hash).
    pub fn verify_proof_for_file(&self, filepath: &str) -> bool {
        let starting_hash = double_hash_from_file(filepath);
        self.verify_proof(starting_hash)
    }
}

impl fmt::Display for MerkleProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MerkleProof:\n")?;
        write!(f, "root hash: {}\n", HexFmt(self.root_hash)).unwrap();
        write!(f, "Proof steps:").unwrap();
        for (i, hash) in self.proof_hashes.iter().enumerate() {
            let direction = if self.proof_directions[i] { "left" } else { "right" };
            write!(f, "\n  {} sibling hash: {}", direction, HexFmt(&hash[..4]))?;
        }      
        Ok(())
    }
}

// The Merkle tree represents its nodes as a vec of MerkleNode objects. The last MerkleNode in the vec is the root node.
// The Merkle tree supports verifying files, producing Merkle proofs for files, and serializing into/deserializing from my custom "fossilized" format. 
// The tree contains an auxilliary hashmap that maps file hashes to tree leaves. This allows for fast verification of files when you don't know a priori which leaf the file's hash was stored in.
#[derive(Debug)]
pub struct MerkleTree {
    pub root_index: NodeHandle,
    pub num_leaves: usize,
    pub nodes: Vec<MerkleNode>,
    hash_lookup: HashMap<[u8; 32], NodeHandle>
}

#[allow(dead_code)]
impl MerkleTree {
    // build tree from bytes. used for testing.
    pub fn new_from_data(data: Vec<&[u8]>) -> Self {
        let num_leaves = data.len();
        let mut nodes: Vec<MerkleNode> = vec![];
        nodes.push(MerkleNode { hash: [0u8; 32], index: 0, left: 0, right: 0, parent: 0 }); // dummy node at index 0
        for (index, d) in data.iter().enumerate() {
            nodes.push(MerkleNode::new_leaf(double_hash(d).into(), index + 1));
        }
        let root_index = MerkleTree::build_tree(&mut nodes, num_leaves, false);
        let hash_lookup = MerkleTree::build_hashmap(&nodes, num_leaves);
        MerkleTree { root_index, num_leaves, nodes, hash_lookup }
    }

    // build tree from a collection of files. Intended to be used with get_filenames_from_directory to produce the vec of filepaths sorted by PG index, but of course you can write your own code to supply it with an arbitrary sequence of files if you wish.
    pub fn new_from_files(filepaths: Vec<&str>) -> Self {
        let num_leaves = filepaths.len();
        let mut nodes: Vec<MerkleNode> = vec![];
        nodes.push(MerkleNode { hash: [0u8; 32], index: 0, left: 0, right: 0, parent: 0 }); // dummy node at index 0
        for (index, filepath) in filepaths.iter().enumerate() {
            nodes.push(MerkleNode::new_leaf_from_file(filepath, index + 1));
        }
        let root_index = MerkleTree::build_tree(&mut nodes, num_leaves, false);
        let hash_lookup = MerkleTree::build_hashmap(&nodes, num_leaves);
        MerkleTree { root_index, num_leaves, nodes, hash_lookup }
    }

    // rebuild tree that has been written to a file in my "fossilized" format. 
    pub fn new_from_fossilized_tree(tree_filename: &str) -> Self {
        let file = File::open(tree_filename).expect("couldn't open fossil tree file");
        let mut reader = BufReader::new(file);
        let mut fossil_hashes: Vec<[u8; 32]> = vec![];

        // need to read first few header lines!
        let mut header_lines: Vec<String> = vec!["".to_string(); 3];
        for i in 0..3 {
            reader.read_line(&mut header_lines[i]).expect("Failed to read line");
        }

        // TODO:check that header lines match format

        let words  = header_lines[1].split_whitespace().collect::<Vec<&str>>();
        let num_leaves: NodeHandle = words[4].parse().expect("Unable to parse num_leaves from line 2 of file");

        // read the fossilized sequence of merkle tree node hashes.
        for line in reader.lines() {
            let clean_line = line.expect("could not read line");
            let fossil_hash = BASE64_STANDARD.decode(clean_line).expect("Could not decode line");
            assert!(fossil_hash.len() == 32, "fossil hash is incorrect length");
            fossil_hashes.push(fossil_hash.try_into().expect("Could not convert to bytes"));
        }

        let mut nodes: Vec<MerkleNode> = vec![];

        // populate the nodes vec with the leaf nodes from the fossil hashes.
        nodes.push(MerkleNode { hash: [0u8; 32], index: 0, left: 0, right: 0, parent: 0 }); // dummy node at index 0
        for (index, hash) in fossil_hashes.iter().enumerate() {
            if index == num_leaves {
                break;
            }
            nodes.push(MerkleNode::new_leaf(*hash, index + 1));
        }
        let root_index = MerkleTree::build_tree(&mut nodes, num_leaves, false);
        let hash_lookup = MerkleTree::build_hashmap(&nodes, num_leaves);
        
        // build the rest of the tree from the leaves
        let tree = MerkleTree { root_index, num_leaves, nodes, hash_lookup };
        tree.verify_tree();

        // make sure all hashes match fossil
        assert!(&tree.get_root_hash() == fossil_hashes.last().unwrap());
        for i in 0..fossil_hashes.len() {
            let fossil_hash = fossil_hashes[i];
            let tree_hash = tree.nodes[i+1].hash;
            if fossil_hash != tree_hash {
                println!("Warning: tree is valid but the hashes don't match those in the fossil file at position {}. That's very weird.", i);
                break;
            }
        }
        tree
    }

    pub fn display_state(nodes: &Vec<MerkleNode>) {
        println!("---Merkle Tree State:----");
        for node in nodes {
            println!("{}", node);
        }
        println!("-------------------------");
    }

    // The above constructors populate the nodes vec with the leaf nodes, and then pass the vec to this function which builds the rest of the tree from the leaves.
    // The constructors only differ in how they get the leaf nodes.
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

    // build the auxilliary hashmap.
    fn build_hashmap(nodes: &Vec<MerkleNode>, num_leaves: usize) -> HashMap<[u8; 32], NodeHandle> {
        let mut hash_lookup = HashMap::<[u8;32],NodeHandle>::new();
        for i in 1..num_leaves + 1 {
            let hash = nodes[i].hash;
            hash_lookup.insert(hash,i);
        }

        hash_lookup
    }

    // return the root hash of the merkle tree.
    pub fn get_root_hash(&self) -> [u8; 32] {
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

    // Returns whether some data was used to build a specific leaf of the merkle tree.
    pub fn verify_with_index(&self, data: &[u8], index: usize) -> bool {
        self.is_a_leaf(&self.nodes[index]) && self.matches_hash(&self.nodes[index], data)
    }

    // returns whether a file was used to build a specific leaf of the merkle tree.
    pub fn verify_with_index_from_file(&self, filepath: &str, index: usize) -> bool {
        self.is_a_leaf(&self.nodes[index]) && self.matches_hash_from_file(&self.nodes[index], filepath)
    }

    // returns whether some data was included in the merkle tree.
    pub fn verify_without_index(&self, data: &[u8]) -> bool {
        let hash = double_hash(data);
        let present = self.hash_lookup.contains_key(&hash);
        present
    }

    // returns whether some file was included in the merkle tree.
    pub fn verify_without_index_from_file(&self, filepath: &str) -> bool {
        let hash = double_hash_from_file(filepath);
        let present = self.hash_lookup.contains_key(&hash);
        present
    }

    // builds a Merkle inclusion proof for some leaf of the tree.
    pub fn produce_proof(&self, index: usize) -> MerkleProof {
        assert!(index != 0);
        let mut proof_hashes = Vec::new();
        let mut proof_directions = Vec::new();
        let mut current_index = index;
        while current_index != self.root_index {
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

        let root_hash = self.get_root_hash();
        MerkleProof { root_hash, proof_hashes, proof_directions }
    }

    // checks that each parent hash follows from its child hashes; i.e., the tree is a valid Merkle tree.
    pub fn verify_tree(&self) {
        for node in self.nodes.iter() {
            if self.is_a_leaf(&node) || node.index == 0 {
                continue;
            }

            assert!(node.left != 0, "node {:x?}", node);
            let left_index = &self.nodes[node.left];
            let left_hash = left_index.hash;
            if node.right > 0 {
                let right_index = &self.nodes[node.right];
                let right_hash = right_index.hash;
                let computed_hash = double_hash(&[left_hash, right_hash].concat());
                assert!(node.hash == computed_hash, 
                    "Merkle tree verification failed.\n 
                    Node {}'s hash does not match the double SHA256 hash of the concatenation of its children's hashes.\n
                    Left child has index {} and hash {}.\n
                    Right child has index {} and hash {}.\n
                    The double SHA256 hash of their concatenated hashes is {}, but parent node {}'s hash is {}.",
                node.index, left_index, HexFmt(left_hash), right_index, HexFmt(right_hash), HexFmt(computed_hash), node.index, HexFmt(node.hash));
            }
            else {
                let computed_hash = double_hash(&[left_hash, left_hash].concat());
                assert!(node.hash == computed_hash, 
                    "Merkle tree verification failed.\n
                    Node {}'s hash does not match the double SHA256 hash of the self-concatenation of its child's hash.\n
                    Left (only) child has index {} and hash {}.\n
                    Concatenating it with itself and double SHA256 hashing gives {}, but parent node {}'s hash is {}.",
                    node.index, left_index, HexFmt(left_hash), HexFmt(computed_hash), node.index, HexFmt(node.hash));
            }
        }
    }

    // Serializes the tree into my "fossilized" format, so named because the goal of the format is to maximize the chance that a useful copy of the serialized tree persists as far into the future as possible. It is designed to be human-readable, relatively compact, simple, self-explanatory, and friendly to write on physical information-storage media such as paper books in addition to hard drives. It is purpose-designed for storing merkle trees only; it is mostly just an in-order list of the node hashes, along with a little metadata and English language explanation of the tree structure.
    pub fn fossilize_tree(&self, tree_filename: &str, date: &str) {
        let mut file = File::create(tree_filename).expect("failed to create file");
        let header_line = format!("# Merkle tree. Created on {} from Project Gutenberg corpus of plain text files.\n", date);
        let num_leaves_line = format!("# Number of leaves: {}\n", self.num_leaves);
        let explain_line = "# Each line below is the hash (in base64) of a merkle node. Tree is binary. Each parent hash is the double SHA256 hash of the concatenation of its two child hashes. If the parent has only one child, its hash is the double SHA256 hash of the child hash concatenated with itself. Final line of file is root hash.\n";
        file.write_all(header_line.as_bytes()).unwrap();
        file.write_all(num_leaves_line.as_bytes()).unwrap();
        file.write_all(explain_line.as_bytes()).unwrap();

        for i in 1..self.nodes.len() {
            let line = format!("{}\n", BASE64_STANDARD.encode(self.nodes[i].hash));
            file.write_all(line.as_bytes()).unwrap();
        }
    }
}