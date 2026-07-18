use hex_fmt::HexFmt;
use sha2::{Sha256, Digest};
use std::{fmt};
use std::fs::{File,read_to_string};
use std::io::{Read,Write,BufReader, prelude::*,};
use std::collections::HashMap;
use base64::prelude::*;
use text_template::Template;

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

// nodes are owned by the 'nodes' vector in the MerkleTree struct. a NodeHandle is a identifier/index for a merkle node in the vector. 1-indexed; 0 means none.
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

// A Merkle proof for a file is the set of hashes you need to apply to the file to reach the root. Constructed only from a TimestampedMerkleTree object, so has no constructor of its own.
#[derive(Debug)]
pub struct MerkleProof {
    pub root_hash: [u8; 32],
    pub proof_hashes: Vec<[u8; 32]>,
    pub proof_directions: Vec<bool>, // true for left, false for right
    pub identifier: String,
    pub num_leaves: NodeHandle,
    pub explain_hash: [u8; 32],
    pub block_height: usize,
    pub tx_hash: [u8; 32],
}

#[allow(dead_code)]
impl MerkleProof {
    pub fn new_from_file(proof_filepath: &str) -> MerkleProof {
        let mut proof_hashes: Vec<[u8; 32]> = vec![];
        let mut proof_directions: Vec<bool> = vec![];

        let file = File::open(proof_filepath).expect("couldn't open proof file");
        let mut reader = BufReader::new(file);

        let mut header_lines: Vec<String> = vec!["".to_string(); 9];
        for i in 0..9 {
            reader.read_line(&mut header_lines[i]).expect("Failed to read line");
        }

        let words  = header_lines[4].split_whitespace().collect::<Vec<&str>>();
        let identifier: &str = words[2];

        let words  = header_lines[5].split_whitespace().collect::<Vec<&str>>();
        let num_leaves: NodeHandle = words[2].parse().expect(&format!("Couldn't parse {} into usize for number of leaves in Merkle tree", words[2]));

        let words  = header_lines[6].split_whitespace().collect::<Vec<&str>>();
        let explain_hash_raw: Vec<u8> = hex::decode(words[3]).expect("couldn't parse explain hash into hex");
        let mut hash_bytes = vec![0u8; 32];
        hash_bytes.copy_from_slice(&explain_hash_raw);
        let explain_hash: [u8; 32] = hash_bytes.try_into().expect("Explain hash length must be 32 bytes");

        let words  = header_lines[7].split_whitespace().collect::<Vec<&str>>();
        let block_height: usize = words[2].parse().expect("Could not parse block height as usize");

        let words  = header_lines[8].split_whitespace().collect::<Vec<&str>>();
        let tx_hash_raw: Vec<u8> = hex::decode(words[2]).expect("couldn't parse tx hash into hex");
        let mut hash_bytes = vec![0u8; 32];
        hash_bytes.copy_from_slice(&tx_hash_raw);
        let tx_hash: [u8; 32] = hash_bytes.try_into().expect("Tx hash length must be 32 bytes");


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

        MerkleProof { root_hash: root_hash_bytes, proof_hashes, proof_directions, identifier: identifier.to_string(), num_leaves, explain_hash, block_height, tx_hash }
    }

    // 
    pub fn fossilize_proof(&self, filename: &str) {
        let proof_template_filepath = "templates/proof_template.txt";
        let template_string = read_to_string(proof_template_filepath).unwrap();
        let template = Template::from(template_string.as_str());

        // identifier: ${identifier}
        // # num_leaves: ${num_leaves}
        // # explain.txt hash: ${explain_hash}
        // # block_height: ${block_height}
        // # tx_hash: ${tx_hash}
        let mut values: HashMap<&str, &str> = HashMap::new();
        values.insert("identifier",&self.identifier);
        let num_leaves_string = format!("{}", self.num_leaves);
        values.insert("num_leaves", &num_leaves_string);
        let explain_hash_string = format!("{}", HexFmt(self.explain_hash));
        values.insert("explain_hash", &explain_hash_string);
        let block_height_string = format!("{}", self.block_height);
        values.insert("block_height", &block_height_string);
        let tx_hash_string = format!("{}", HexFmt(self.tx_hash));
        values.insert("tx_hash", &tx_hash_string);

        let text = template.try_fill_in(&values).unwrap().to_string();

        let mut file = File::create(filename).expect("failed to create file");
        file.write_all(&text.into_bytes()).expect("couldn't write file");

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
        if computed_hash != self.root_hash {
            println!("Computed hash doesn't match root hash. Proof verification failed.");
            return false;
        }
        true
    }

    // verifies that some data is part of a merkle tree (represented by its root hash).
    pub fn verify_proof_for_data(&self, data: &[u8], autoaccept: bool) -> bool {
        let starting_hash = double_hash(data);
        if !self.verify_proof(starting_hash){
            false
        }
        else if autoaccept {
            println!("Input data properly hashes up the tree to the root.");
            println!("Autoaccepting the blockchain verification process for testing purposes. DO NOT TRUST THIS RESULT AS A SECURE TIMESTAMP.");
            true
        }
        else {
            crate::verify::verify_proof_timestamp(&self)
        }
    }

    // verifies that some file is part of a merkle tree (represented by its root hash).
    pub fn verify_proof_for_file(&self, filepath: &str, autoaccept: bool) -> bool {
        let starting_hash = double_hash_from_file(filepath);
        if !self.verify_proof(starting_hash) {
            false
        }
        else if autoaccept {
            println!("Input data properly hashes up the tree to the root.");
            println!("Autoaccepting the blockchain verification process for testing purposes. DO NOT TRUST THIS RESULT AS A SECURE TIMESTAMP.");
            true
        }
        else {
            crate::verify::verify_proof_timestamp(&self)
        }
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

    fn new_from_tree_file_suffix(reader: BufReader<File>, num_leaves: usize) -> MerkleTree {
        let mut fossil_hashes: Vec<[u8; 32]> = vec![];
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

    // rebuild tree that has been written to a file in my "fossilized" format. 
    pub fn new_from_unfinished_tree_file(tree_filename: &str) -> Self {
        let file = File::open(tree_filename).expect("couldn't open fossil tree file");
        let mut reader = BufReader::new(file);

        // need to read first few header lines!
        let mut header_lines: Vec<String> = vec!["".to_string(); 3];
        for i in 0..3 {
            reader.read_line(&mut header_lines[i]).expect("Failed to read line");
        }

        // TODO:check that header lines match format

        let words  = header_lines[1].split_whitespace().collect::<Vec<&str>>();
        let num_leaves: NodeHandle = words[4].parse().expect("Unable to parse num_leaves from line 2 of file");

        Self::new_from_tree_file_suffix(reader, num_leaves)
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

    // returns whether some data was included in the merkle tree.
    pub fn verify(&self, data: &[u8]) -> bool {
        let hash = double_hash(data);
        let present = self.hash_lookup.contains_key(&hash);
        present
    }

    // returns whether some file was included in the merkle tree.
    pub fn verify_from_file(&self, filepath: &str) -> bool {
        let hash = double_hash_from_file(filepath);
        let present = self.hash_lookup.contains_key(&hash);
        present
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
    pub fn write_unfinished_tree_to_file(&self, tree_filename: &str, date: &str,) {
        let unfinished_merkle_template_filepath = "templates/unfinished_merkle_template.txt";
        let template_string = read_to_string(unfinished_merkle_template_filepath).unwrap();
        let template = Template::from(template_string.as_str());

        let mut values: HashMap<&str, &str> = HashMap::new();
        values.insert("date",date);
        let num_leaves_string = format!("{}", self.num_leaves);
        values.insert("num_leaves", &num_leaves_string);
        let text = template.try_fill_in(&values).unwrap().to_string();

        let mut file = File::create(tree_filename).expect("failed to create file");
        file.write_all(&text.into_bytes()).expect("couldn't write file");

        for i in 1..self.nodes.len() {
            let line = format!("{}\n", BASE64_STANDARD.encode(self.nodes[i].hash));
            file.write_all(line.as_bytes()).unwrap();
        }
    }

}

pub struct TimestampedMerkleTree {
    pub tree: MerkleTree,
    pub identifier: String,
    pub block_height: usize,
    pub tx_hash: [u8; 32],
    verified_timestamp: bool,
}

#[allow(dead_code)]
impl TimestampedMerkleTree {
    // read a merkle tree from a file. 
    pub fn new(tree: MerkleTree, identifier: &str, block_height: usize, tx_hash: [u8; 32]) -> TimestampedMerkleTree {
        TimestampedMerkleTree { tree, identifier: identifier.to_string(), block_height, tx_hash, verified_timestamp: false }
    }

    pub fn new_from_fossilized_tree(fossil_filepath: &str) -> TimestampedMerkleTree {
        let file = File::open(fossil_filepath).expect("couldn't open fossil tree file");
        let mut reader = BufReader::new(file);

        // need to read first few header lines!
        let mut header_lines: Vec<String> = vec!["".to_string(); 6];
        for i in 0..6 {
            reader.read_line(&mut header_lines[i]).expect("Failed to read line");
        }

        let words  = header_lines[1].split_whitespace().collect::<Vec<&str>>();
        let num_leaves: NodeHandle = words[4].parse().expect("Unable to parse num_leaves from line 2 of file");
        let words = header_lines[2].split_whitespace().collect::<Vec<&str>>();
        let identifier = words[10];
        let words = header_lines[3].split_whitespace().collect::<Vec<&str>>();
        let block_height: usize = words[3].parse().expect("Unable to parse num_leaves from line 2 of file");
        let words = header_lines[4].split_whitespace().collect::<Vec<&str>>();
        let tx_hash_string = words[3];
        let tx_hash = hex::decode(tx_hash_string).unwrap();
        let mut hash_bytes = vec![0u8; 32];
        hash_bytes.copy_from_slice(&tx_hash);
        let hash_bytes_length: [u8; 32] = hash_bytes.try_into().expect("Hash length must be 32 bytes");

        let tree = MerkleTree::new_from_tree_file_suffix(reader, num_leaves);
        tree.verify_tree();
        Self::new(tree, identifier, block_height, hash_bytes_length)
    }

    pub fn is_verified(&self) {
        self.verified_timestamp;
    }

    pub fn verify_timestamp(&mut self, explain_filepath: &str, autoaccept: bool) -> bool {
        if autoaccept {
            println!("Autoaccepting the blockchain verification process for testing purposes. DO NOT TRUST THIS RESULT AS A SECURE TIMESTAMP.");
            return true;
        }
        
        let explainer_hash = double_hash_from_file(explain_filepath);
        let result = crate::verify::verify_tree_timestamp(&self.identifier, &self.tree, explainer_hash, self.tx_hash);
        if !result{
            // println!("Failed to verify the timestamp on the blockchain. Deleting timestamped merkle tree file. {}", tree_filename);
            // std::fs::remove_file(tag_tree_filename).unwrap();
            println!("Failed to verify the timestamp on the blockchain.");
        }
        else {
            self.verified_timestamp = true;
        }
        result
    }

    // Serializes the tree into my "fossilized" format, so named because the goal of the format is to maximize the chance that a useful copy of the serialized tree persists as far into the future as possible. It is designed to be human-readable, relatively compact, simple, self-explanatory, and friendly to write on physical information-storage media such as paper books in addition to hard drives. It is purpose-designed for storing merkle trees only; it is mostly just an in-order list of the node hashes, along with a little metadata and English language explanation of the tree structure.
    pub fn fossilize_tree(&self, tree_filename: &str, date: &str) {
        let merkle_template_filepath = "templates/merkle_template.txt";
        let template_string = read_to_string(merkle_template_filepath).unwrap();
        let template = Template::from(template_string.as_str());

        let mut values: HashMap<&str, &str> = HashMap::new();
        values.insert("date",date);
        let num_leaves_string = format!("{}", self.tree.num_leaves);
        values.insert("num_leaves", &num_leaves_string);
        values.insert("identifier", &self.identifier);
        let block_height_string = format!("{}", self.block_height);
        values.insert("block_height", &block_height_string);
        let tx_hash_string = format!("{}", HexFmt(self.tx_hash));
        values.insert("tx_hash", &tx_hash_string);
        let text = template.try_fill_in(&values).unwrap().to_string();

        let mut file = File::create(tree_filename).expect("failed to create file");
        file.write_all(&text.into_bytes()).expect("couldn't write file");

        for i in 1..self.tree.nodes.len() {
            let line = format!("{}\n", BASE64_STANDARD.encode(self.tree.nodes[i].hash));
            file.write_all(line.as_bytes()).unwrap();
        }
    }

    // builds a Merkle inclusion proof for some leaf of the tree, complete with the required info to verify the timestamp on the blockchain.
    pub fn produce_proof(&self, index: NodeHandle, explain_hash: [u8; 32]) -> MerkleProof {

        assert!(index != 0);
        let mut proof_hashes = Vec::new();
        let mut proof_directions = Vec::new();
        let mut current_index = index;
        while current_index != self.tree.root_index {
            let parent_index = self.tree.nodes[current_index].parent;
            let sibling_index = if self.tree.nodes[parent_index].left == current_index {
                self.tree.nodes[parent_index].right
            } else {
                self.tree.nodes[parent_index].left
            };
            if sibling_index == 0 {
                proof_hashes.push(self.tree.nodes[current_index].hash);
            }
            else {
                proof_hashes.push(self.tree.nodes[sibling_index].hash);
            }
            proof_directions.push(self.tree.nodes[parent_index].left == current_index);
            current_index = parent_index;
        }

        let root_hash = self.tree.get_root_hash();
        MerkleProof { root_hash, proof_hashes, proof_directions, identifier: self.identifier.clone(), num_leaves: self.tree.num_leaves, explain_hash: explain_hash, block_height: self.block_height, tx_hash: self.tx_hash}
    }

    pub fn produce_proof_from_file(&self, filepath: &str, explain_hash: [u8; 32]) -> MerkleProof {
        let starting_hash = double_hash_from_file(filepath);
        let index: NodeHandle = *self.tree.hash_lookup.get(&starting_hash).expect("File hash not found in Merkle tree.");
        self.produce_proof(index, explain_hash)
    }

    pub fn produce_proof_from_data(&self, data: &[u8], explain_hash: [u8; 32]) -> MerkleProof {
        let starting_hash = double_hash(data);
        let index: NodeHandle = *self.tree.hash_lookup.get(&starting_hash).expect("File hash not found in Merkle tree.");
        self.produce_proof(index, explain_hash)
    }
}
