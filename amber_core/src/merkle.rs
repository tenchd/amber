use hex_fmt::HexFmt;
use sha2::{Sha256, Digest};
use std::{fmt, println};
use std::path::Path;
use std::fs::{File,read_to_string};
use std::io::{Read,Write,BufReader, prelude::*,};
use std::collections::HashMap;
use base64::prelude::*;
use text_template::Template;

use crate::AMBER_VERSION;
use crate::FailureReason;

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
pub fn double_hash_from_file(filepath: &str) -> (Option<[u8; 32]>, FailureReason) {
    let file_result = File::open(filepath);
    if file_result.is_err() {
        println!("Could not find file to hash at location {}", filepath);
        return (None, FailureReason::FileNotFound)
    }
    let mut file = file_result.unwrap();
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024]; // Process in 1KB chunks

    loop {
            let bytes_read_result = file.read(&mut buffer);
            if bytes_read_result.is_err() {
                println!("Could not read file to hash at location {}", filepath);
                return (None, FailureReason::FileNotFound)
            }
            let bytes_read = bytes_read_result.unwrap();
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
    (Some(hash_bytes_length), FailureReason::Success)
}

pub fn parse_hash_from_str(input_string: &str) -> (Option<[u8; 32]>, FailureReason) {
    let mut hash = [0u8; 32];
    let result = hex::decode_to_slice(input_string, &mut hash);
    let reason;
    match result {
        Ok(_) => {
            reason = FailureReason::Success;
            return (Some(hash), reason);
        },
        Err(_) => {
            println!("Unable to parse tx hash {} into hex", input_string);
            reason = FailureReason::TxHashNotParseable;
            return (None, reason);
        },
    }
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
        let hash = double_hash_from_file(filepath).0.unwrap();
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
    pub utc_timestamp: i64,
    pub tx_hash: [u8; 32],
}

#[allow(dead_code)]
impl MerkleProof {
    pub fn new_from_file(proof_filepath: &str) -> (Option<MerkleProof>, FailureReason) {
        let mut proof_hashes: Vec<[u8; 32]> = vec![];
        let mut proof_directions: Vec<bool> = vec![];


        let file_result = File::open(proof_filepath);
        if file_result.is_err() {
            println!("Couldn't find proof file at location {}", proof_filepath);
            return (None, FailureReason::ProofFileNotFound);
        }
        let file = file_result.unwrap();
        let mut reader = BufReader::new(file);

        let mut header_lines: Vec<String> = vec!["".to_string(); 11];
        for i in 0..11 {
            let result = reader.read_line(&mut header_lines[i]);
            if result.is_err() {
                println!("Proof file has too few lines. Expected at least 11 header lines but only read {}", i);
                return (None, FailureReason::ProofFileNotParseable)
            }
        }

        let words  = header_lines[4].split_whitespace().collect::<Vec<&str>>();
        let identifier: &str = words[2];

        let words  = header_lines[5].split_whitespace().collect::<Vec<&str>>();
        let num_leaves_result = words[2].parse::<NodeHandle>();
        if num_leaves_result.is_err() {
            println!("Could not parse number of leaves header line: {:?}", words);
            return (None, FailureReason::ProofFileNotParseable)
        }
        let num_leaves = num_leaves_result.unwrap();

        let words  = header_lines[6].split_whitespace().collect::<Vec<&str>>();
        let (explain_hash, _) = parse_hash_from_str(words[3]);
        if explain_hash.is_none() {
            println!("Could not parse explain hash header line: {:?}", words);
            return (None, FailureReason::ProofFileNotParseable);
        }

        let words  = header_lines[7].split_whitespace().collect::<Vec<&str>>();
        let block_height_result = words[2].parse::<usize>();
        if block_height_result.is_err() {
            println!("Could not parse block height header line: {:?}", words);
            return (None, FailureReason::ProofFileNotParseable)
        }
        let block_height = block_height_result.unwrap();

        let words  = header_lines[8].split_whitespace().collect::<Vec<&str>>();
        let (tx_hash, _) = parse_hash_from_str(words[2]);
        if tx_hash.is_none() {
            println!("Could not parse tx hash header line: {:?}", words);
            return (None, FailureReason::ProofFileNotParseable);
        }

        let words  = header_lines[9].split_whitespace().collect::<Vec<&str>>();
        let utc_timestamp_result = words[2].parse::<i64>();
        if utc_timestamp_result.is_err() {
            println!("Could not parse utc timestamp header line: {:?}", words);
            return (None, FailureReason::ProofFileNotParseable)
        }
        let utc_timestamp = utc_timestamp_result.unwrap();
        

        let words = header_lines[10].split_whitespace().collect::<Vec<&str>>();
        let _version: &str = words[5];


        let mut root_hash_line: String = "".to_string();
        let result = reader.read_line(&mut root_hash_line);
        if result.is_err() {
            println!("Expected root hash line after headers");
            return (None, FailureReason::ProofFileNotParseable)
        }
        root_hash_line = root_hash_line.trim_end().to_string();
        let root_hash_result = BASE64_STANDARD.decode(&root_hash_line);
        if root_hash_result.is_err() {
            println!("Could not parse explain hash header line: {:?}", &root_hash_line);
            return (None, FailureReason::ProofFileNotParseable)
        }
        let root_hash = root_hash_result.unwrap();
        let root_hash_bytes: [u8; 32] = match root_hash.try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                println!("Could not parse root hash into bytes");
                return (None, FailureReason::ProofFileNotParseable);
            }
        };

        let mut counter = 13;
        for line in reader.lines() {
            let clean_line = line.expect("could not read line");
            let parts: Vec<&str> = clean_line.split(',').collect();
            if parts.len() != 2 {
                println!("proof line {} does not have two parts separated by comma", counter);
                return (None, FailureReason::ProofFileNotParseable);
            }
            let fossil_hash_result = BASE64_STANDARD.decode(parts[0]);
            if fossil_hash_result.is_err() {
                println!("Failed to parse hash in proof line {}", counter);
                return (None, FailureReason::ProofFileNotParseable);
            }
            let fossil_hash = fossil_hash_result.unwrap();
            if fossil_hash.len() != 32 {
                println!("fossil hash on line {} is incorrect length", counter);
                return (None, FailureReason::ProofFileNotParseable);
            }
            let bytes_result: [u8; 32] = match fossil_hash.try_into() {
                Ok(bytes) => bytes,
                Err(_) => {
                    println!("fossil hash on line {} failed to parse into bytes", counter);
                    return (None, FailureReason::ProofFileNotParseable);
                }
            };
            proof_hashes.push(bytes_result);
            let direction = match parts[1].trim().parse::<bool>(){
                Ok(boolean) => boolean,
                Err(_) => {
                    println!("bool on line {} is not parseable", counter);
                    return (None, FailureReason::ProofFileNotParseable);
                }
            };
            proof_directions.push(direction);
            counter += 1;
        }

        let proof = MerkleProof { root_hash: root_hash_bytes, proof_hashes, proof_directions, identifier: identifier.to_string(), num_leaves, explain_hash: explain_hash.unwrap(), block_height, utc_timestamp, tx_hash: tx_hash.unwrap() };
        (Some(proof), FailureReason::Success)
    }

    // 
    pub fn fossilize_proof(&self, filename: &str, corpus_name: &str) {
        let proof_template_filepath = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixed_templates/proof_template.txt");
        let template_string = read_to_string(&proof_template_filepath).expect(&format!("Tried to find {:?}", &proof_template_filepath));
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
        values.insert("corpus_name", corpus_name);
        let version_string = &AMBER_VERSION.to_string();
        values.insert("version", version_string);
        let utc_timestamp_string = self.utc_timestamp.to_string();
        values.insert("chain_utc_timestamp", &utc_timestamp_string);

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
    pub fn verify_proof(&self, starting_hash: [u8; 32], verbose: bool) -> bool {
        let mut computed_hash = starting_hash;
        for (i, sibling_hash) in self.proof_hashes.iter().enumerate() {
            if self.proof_directions[i] {
                computed_hash = double_hash(&[computed_hash, *sibling_hash].concat());
            } else {
                computed_hash = double_hash(&[*sibling_hash, computed_hash].concat());
            }
        }
        if computed_hash != self.root_hash {
            if verbose {println!("Computed hash doesn't match root hash. Proof verification failed.");}
            return false;
        }
        true
    }

    // verifies that some data is part of a merkle tree (represented by its root hash).
    pub fn verify_proof_for_data(&self, data: &[u8], autoaccept: bool, verbose: bool) -> (bool, FailureReason) {
        let starting_hash = double_hash(data);
        if !self.verify_proof(starting_hash, verbose){
            println!("File hash does not match first hash in proof file");
            (false, FailureReason::FileHashMismatch)
        }
        else if autoaccept {
            println!("Input data properly hashes up the tree to the root.");
            println!("Autoaccepting the blockchain verification process for testing purposes. DO NOT TRUST THIS RESULT AS A SECURE TIMESTAMP.");
            (true, FailureReason::AutoAccept)
        }
        else {
            crate::verify::verify_proof_timestamp(&self, verbose)
        }
    }

    // verifies that some file is part of a merkle tree (represented by its root hash).
    pub fn verify_proof_for_file(&self, filepath: &str, autoaccept: bool, verbose: bool) -> (bool, FailureReason) {
        let (result, reason) = double_hash_from_file(filepath);
        if result.is_none() {
            return (false, reason)
        }
        let starting_hash = result.unwrap();
        if !self.verify_proof(starting_hash, verbose) {
            println!("File hash does not match first hash in proof file");
            (false, FailureReason::FileHashMismatch)
        }
        else if autoaccept {
            if verbose {
                println!("Input data properly hashes up the tree to the root.");
                println!("Autoaccepting the blockchain verification process for testing purposes. DO NOT TRUST THIS RESULT AS A SECURE TIMESTAMP.");
            }
            (true, FailureReason::AutoAccept)
        }
        else {
            crate::verify::verify_proof_timestamp(&self, verbose)
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
    pub fn new_from_files(filepaths: Vec<&str>) -> (Option<Self>, FailureReason) {
        let num_leaves = filepaths.len();
        let mut nodes: Vec<MerkleNode> = vec![];
        nodes.push(MerkleNode { hash: [0u8; 32], index: 0, left: 0, right: 0, parent: 0 }); // dummy node at index 0
        for (index, filepath) in filepaths.iter().enumerate() {
            nodes.push(MerkleNode::new_leaf_from_file(filepath, index + 1));
        }
        let root_index = MerkleTree::build_tree(&mut nodes, num_leaves, false);
        let hash_lookup = MerkleTree::build_hashmap(&nodes, num_leaves);
        (Some(MerkleTree { root_index, num_leaves, nodes, hash_lookup }), FailureReason::Success)
    }

    fn new_from_tree_file_suffix(reader: BufReader<File>, num_leaves: usize, full: bool) -> (Option<Self>, FailureReason) {
        let mut fossil_hashes: Vec<[u8; 32]> = vec![];
        // read the fossilized sequence of merkle tree node hashes.
        let mut counter = 0;
        for line in reader.lines() {
            let clean_line = line.expect("could not read line");
            let fossil_hash_result = BASE64_STANDARD.decode(clean_line);
            if fossil_hash_result.is_err() {
                println!("Could not parse {}th hash line as base64", counter);
                return (None, FailureReason::MerkleFileNotParseable)
            }
            let fossil_hash = fossil_hash_result.unwrap();
            if fossil_hash.len() != 32 {
                println!("{}th fossil hash is incorrect length", counter);
                return (None, FailureReason::MerkleFileNotParseable)
            }
            let hash: [u8; 32] = match fossil_hash.try_into() {
                Ok(value) => value,
                Err(_) => {
                    println!("couldn't parse {}th hash line as bytes", counter);
                    return (None, FailureReason::MerkleFileNotParseable)
                }
            };
            fossil_hashes.push(hash);
            counter += 1;
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

        if full {
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
        }
        (Some(tree), FailureReason::Success)
    }

    // rebuild tree that has been written to a file in my "fossilized" format. 
    pub fn new_from_unfinished_tree_file(tree_filename: &str) -> (Option<Self>, FailureReason) {
        let file_result = File::open(tree_filename);
        if file_result.is_err() {
            println!("Couldn't open unfinished merkle tree file at location {}", tree_filename);
            return (None, FailureReason::MerkleFileNotFound)
        }
        let file = file_result.unwrap();
        let mut reader = BufReader::new(file);

        // need to read first few header lines!
        let mut header_lines: Vec<String> = vec!["".to_string(); 3];
        for i in 0..3 {
            let result = reader.read_line(&mut header_lines[i]);
            if result.is_err() {
                println!("Unfinished merkle tree file at location {} has fewer than 3 lines", tree_filename);
                return (None, FailureReason::MerkleFileNotParseable)
            }
        }

        // TODO:check that header lines match format

        let words  = header_lines[1].split_whitespace().collect::<Vec<&str>>();
        let num_leaves_result = words[4].parse::<NodeHandle>();
        if num_leaves_result.is_err() {
            println!("Couldn't parse num_leaves header line {:?} in unfinished merkle tree file", words);
            return (None, FailureReason::MerkleFileNotParseable)
        }
        let num_leaves = num_leaves_result.unwrap();

        Self::new_from_tree_file_suffix(reader, num_leaves, true)
    }

    // builds tree from a file that simply lists the leaf hashes. Used for "blind" tree construction when user does not want to reveal the files that were hashed.
    pub fn new_from_hashes(hashes_filepath: &str) -> (Option<Self>, FailureReason) {
        let file_result = File::open(hashes_filepath);
        if file_result.is_err() {
            println!("Couldn't open leaf hashes file at location {}", hashes_filepath);
            return (None, FailureReason::MerkleFileNotFound)
        }
        let file = file_result.unwrap();
        let mut reader = BufReader::new(file);

        let mut first_line = "".to_string();
        let result = reader.read_line(&mut first_line);
        if result.is_err() {
            println!("Couldn't parse num_leaves header line {:?} in leaf hashes file", first_line);
            return (None, FailureReason::MerkleFileNotParseable)
        }
        first_line.pop();
        let num_leaves_result = first_line.parse::<usize>();
        if num_leaves_result.is_err() {
            println!("Couldn't parse num_leaves header line {:?} in leaf hashes file", first_line);
            return (None, FailureReason::MerkleFileNotParseable)
        }
        let num_leaves = num_leaves_result.unwrap();

        Self::new_from_tree_file_suffix(reader, num_leaves, false)
    }

    pub fn new_empty() -> Self {
        let hash_lookup = std::collections::HashMap::<[u8;32],usize>::new();
        MerkleTree{root_index: 0, num_leaves: 1, nodes: vec![], hash_lookup: hash_lookup}
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

    // fn matches_hash_from_file(&self, node: &MerkleNode, filepath: &str) -> bool {
    //     let leaf_hash = double_hash_from_file(filepath);
    //     node.hash == leaf_hash
    // }

    // returns whether some data was included in the merkle tree.
    pub fn verify(&self, data: &[u8]) -> bool {
        let hash = double_hash(data);
        let present = self.hash_lookup.contains_key(&hash);
        present
    }

    // returns whether some file was included in the merkle tree.
    pub fn verify_from_file(&self, filepath: &str) -> bool {
        let (result, _) = double_hash_from_file(filepath);
        if result.is_none() {
            return false;
        }
        let hash = result.unwrap();
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

    pub fn write_leaf_hashes_to_file(&self, leaf_hash_filename: &str) -> FailureReason {
        let file_result = File::create(leaf_hash_filename);
        if file_result.is_err() {
            println!("Failed to write leaf hashes to location {}", leaf_hash_filename);
            return FailureReason::PathNotWriteable;
        }
        let mut file = file_result.unwrap();
        let num_leaves_line = format!("{}\n", self.num_leaves);
        let result = file.write_all(&num_leaves_line.into_bytes());
        if result.is_err() {
            println!("Failed to write leaf hashes to location {}", leaf_hash_filename);
            return FailureReason::PathNotWriteable;
        }

        for i in 1..self.num_leaves + 1 {
            let line = format!("{}\n", BASE64_STANDARD.encode(self.nodes[i].hash));
            let result = file.write_all(line.as_bytes());
            if result.is_err() {
                println!("Failed to write leaf hashes to location {}", leaf_hash_filename);
                return FailureReason::PathNotWriteable;
            }
        }

        FailureReason::Success
    }

    // Serializes the tree into my "fossilized" format, so named because the goal of the format is to maximize the chance that a useful copy of the serialized tree persists as far into the future as possible. It is designed to be human-readable, relatively compact, simple, self-explanatory, and friendly to write on physical information-storage media such as paper books in addition to hard drives. It is purpose-designed for storing merkle trees only; it is mostly just an in-order list of the node hashes, along with a little metadata and English language explanation of the tree structure.
    pub fn write_unfinished_tree_to_file(&self, tree_filename: &str, date: &str,) -> FailureReason {
        let unfinished_merkle_template_filepath = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixed_templates/unfinished_merkle_template.txt");
        let template_string = read_to_string(unfinished_merkle_template_filepath).unwrap();
        let template = Template::from(template_string.as_str());

        let mut values: HashMap<&str, &str> = HashMap::new();
        values.insert("date",date);
        let num_leaves_string = format!("{}", self.num_leaves);
        values.insert("num_leaves", &num_leaves_string);
        let text = template.try_fill_in(&values).unwrap().to_string();

        let file_result = File::create(tree_filename);
        if file_result.is_err() {
            println!("Failed to write unfinished merkle tree to location {}", tree_filename);
            return FailureReason::PathNotWriteable;
        }
        let mut file = file_result.unwrap();
        let result = file.write_all(&text.into_bytes());
        if result.is_err() {
            println!("Failed to write unfinished merkle tree to location {}", tree_filename);
            return FailureReason::PathNotWriteable;
        }

        for i in 1..self.nodes.len() {
            let line = format!("{}\n", BASE64_STANDARD.encode(self.nodes[i].hash));
            let result = file.write_all(line.as_bytes());
            if result.is_err() {
            println!("Failed to write unfinished merkle tree to location {}", tree_filename);
                return FailureReason::PathNotWriteable;
            }
        }
        FailureReason::Success
    }

}

pub struct TimestampedMerkleTree {
    pub tree: MerkleTree,
    pub identifier: String,
    pub block_height: usize,
    pub tx_hash: [u8; 32],
    pub explain_hash: [u8; 32],
    pub utc_timestamp: i64,
    verified_timestamp: bool,
}

#[allow(dead_code)]
impl TimestampedMerkleTree {
    // read a merkle tree from a file. 
    pub fn new(tree: MerkleTree, identifier: &str, utc_raw: i64, block_height: usize, tx_hash: [u8; 32], explain_hash: [u8; 32]) -> TimestampedMerkleTree {
        TimestampedMerkleTree { tree, identifier: identifier.to_string(), block_height, tx_hash, explain_hash, utc_timestamp: utc_raw, verified_timestamp: false }
    }

    pub fn new_without_time(tree: MerkleTree, identifier: &str, tx_hash: [u8; 32], explain_hash: [u8; 32]) -> TimestampedMerkleTree {
        let utc_raw = chrono::Utc::now();
        let block_height = 0;
        TimestampedMerkleTree::new(tree, identifier, utc_raw.timestamp(), block_height, tx_hash, explain_hash)
    }

    pub fn new_from_fossilized_tree(fossil_filepath: &str) -> (Option<TimestampedMerkleTree>, FailureReason) {
        let file_result = File::open(fossil_filepath);
        let file;
        match file_result {
            Ok(value) => {
                file = value;
            },
            Err(_) => {
            println!("Could not find merkle tree file at location {}", fossil_filepath);
                return (None, FailureReason::MerkleFileNotFound);
            },
        }
        let mut reader = BufReader::new(file);

        // need to read first few header lines!
        let mut header_lines: Vec<String> = vec!["".to_string(); 9];
        for i in 0..9 {
            let result = reader.read_line(&mut header_lines[i]);
            if result.is_err() {
                println!("Expected 9 header lines in merkle tree file but only read {}", i);
                return (None, FailureReason::MerkleFileNotParseable)
            }
        }

        let words  = header_lines[1].split_whitespace().collect::<Vec<&str>>();
        let num_leaves_result = words[4].parse::<NodeHandle>();
        if num_leaves_result.is_err() {
            println!("Could not parse num_leaves header line: {:?}", words);
            return (None, FailureReason::MerkleFileNotParseable)
        }
        let num_leaves = num_leaves_result.unwrap();

        let words = header_lines[2].split_whitespace().collect::<Vec<&str>>();
        let identifier = words[10];
        let words = header_lines[3].split_whitespace().collect::<Vec<&str>>();
        let block_height_result = words[3].parse::<usize>();
        if block_height_result.is_err() {
            println!("Could not parse block height header line: {:?}", words);
            return(None, FailureReason::MerkleFileNotParseable)
        }
        let block_height = block_height_result.unwrap();

        let words = header_lines[4].split_whitespace().collect::<Vec<&str>>();
        let tx_hash_string = words[3];
        let (tx_hash_result, reason) = parse_hash_from_str(tx_hash_string);
        if tx_hash_result.is_none() {
            return (None, reason);
        }
        let tx_hash = tx_hash_result.unwrap();

        let words = header_lines[5].split_whitespace().collect::<Vec<&str>>();
        let utc_timestamp_result = words[3].parse::<i64>();
        if utc_timestamp_result.is_err() {
            println!("Could not parse utc timestamp header line: {:?}", words);
            return (None, FailureReason::MerkleFileNotParseable)
        }
        let utc_timestamp = utc_timestamp_result.unwrap();

        let words = header_lines[6].split_whitespace().collect::<Vec<&str>>();
        let explain_hash_string = words[3];
        let (explain_hash_result, reason) = parse_hash_from_str(explain_hash_string);
        if explain_hash_result.is_none() {
            return (None, reason);
        }
        let explain_hash = explain_hash_result.unwrap();

        let words = header_lines[7].split_whitespace().collect::<Vec<&str>>();
        let _version: &str = words[3];

        let (tree_result, tree_reason) = MerkleTree::new_from_tree_file_suffix(reader, num_leaves, true);
        if tree_result.is_none() {
            return (None, tree_reason)
        }
        let tree = tree_result.unwrap();
        tree.verify_tree();
        (Some(Self::new(tree, identifier, utc_timestamp, block_height, tx_hash, explain_hash)), FailureReason::Success) //note for tomorrow: read utctimestamp from fossil file and then add it to this call
    }

    pub fn is_verified(&self) -> bool {
        self.verified_timestamp
    }

    pub fn verify_timestamp(&mut self, explain_filepath: &str, autoaccept: bool) -> (bool, FailureReason) {
        if autoaccept {
            println!("Autoaccepting the blockchain verification process for testing purposes. DO NOT TRUST THIS RESULT AS A SECURE TIMESTAMP.");
            return (true, FailureReason::AutoAccept);
        }
        
        let (result, reason) = double_hash_from_file(explain_filepath);
        if result.is_none() {
            return (false, reason)
        }
        let observed_explain_hash = result.unwrap();
        if observed_explain_hash != self.explain_hash {
            println!("Failed to verify: explain.txt does not match explain hash in merkle tree file");
            return (false, FailureReason::ExplainHashMismatch);
        }

        let (result, reason) = crate::verify::verify_tree_timestamp(&self.identifier, &self.tree, self.explain_hash, self.tx_hash);
        match result {
            Some(timestamp_details) => {
                let success_reason;

                if self.block_height == 0 {
                    self.block_height = timestamp_details.block_height;
                    success_reason = FailureReason::Success;
                }
                else {
                    if self.block_height != timestamp_details.block_height {
                        println!("WARNING: the block height in the fossil file does not match the true block height of the transaction containing the timestamp. The fossil file says the block height is {}, but the true block height is {}", self.block_height, timestamp_details.block_height);
                        success_reason = FailureReason::BlockHeightMismatchNonFatal;
                    }
                    else {
                        success_reason = FailureReason::Success;
                    }
                }
                self.utc_timestamp = timestamp_details.timestamp;
                self.verified_timestamp = true;
                let utc = chrono::DateTime::from_timestamp(timestamp_details.timestamp, 0).unwrap();
                let date = format!("{}", utc.format("%B %e, %Y").to_string());
                let time = format!("{}", utc.format("%H:%M").to_string());
                println!("Timestamp has been verified on the blockchain. Transaction found in block {} on {} at {}", timestamp_details.block_height, date, time);
                return (true, success_reason);
            }
            _ => {
                println!("Failed to verify the timestamp on the blockchain.");
                return (false, reason);
            }
        }
        
    }

    // Serializes the tree into my "fossilized" format, so named because the goal of the format is to maximize the chance that a useful copy of the serialized tree persists as far into the future as possible. It is designed to be human-readable, relatively compact, simple, self-explanatory, and friendly to write on physical information-storage media such as paper books in addition to hard drives. It is purpose-designed for storing merkle trees only; it is mostly just an in-order list of the node hashes, along with a little metadata and English language explanation of the tree structure.
    pub fn fossilize_tree(&self, tree_filename: &str, corpus_name: &str) -> FailureReason {
        if !(self.is_verified()) {
            println!("!!!!!!!!!!");
            println!("WARNING: You are fossilizing an unverified timestamped merkle tree. You should only be doing this as a test. There is no guarantee that the resulting fossil file will verify on the blockchain.");
            println!("!!!!!!!!!!");
        }
        let merkle_template_filepath = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixed_templates/merkle_template.txt");
        let template_string = read_to_string(merkle_template_filepath).unwrap();
        let template = Template::from(template_string.as_str());

        let utc = chrono::DateTime::from_timestamp(self.utc_timestamp, 0).unwrap();
        let date = format!("{}", utc.format("%B%e, %Y").to_string());

        let utc_string = self.utc_timestamp.to_string();

        let mut values: HashMap<&str, &str> = HashMap::new();
        values.insert("chain_utc_timestamp", &utc_string);
        values.insert("date",&date);
        let num_leaves_string = format!("{}", self.tree.num_leaves);
        values.insert("num_leaves", &num_leaves_string);
        values.insert("identifier", &self.identifier);
        let block_height_string = format!("{}", self.block_height);
        values.insert("block_height", &block_height_string);
        let tx_hash_string = format!("{}", HexFmt(self.tx_hash));
        values.insert("tx_hash", &tx_hash_string);
        let explain_hash_string = format!("{}", HexFmt(self.explain_hash));
        values.insert("explain_hash", &explain_hash_string);
        values.insert("corpus_name", corpus_name);
        let version_string = &AMBER_VERSION.to_string();
        values.insert("version", version_string);

        let text = template.try_fill_in(&values).unwrap().to_string();

        let file_result = File::create(tree_filename);
        if file_result.is_err() {
            println!("Could not write fossilized tree file to location {}", tree_filename);
            return FailureReason::PathNotWriteable
        }
        let mut file = file_result.unwrap();
        let result = file.write_all(&text.into_bytes());
        if result.is_err() {
            println!("Could not write fossilized tree file to location {}", tree_filename);
            return FailureReason::PathNotWriteable
        }

        for i in 1..self.tree.nodes.len() {
            let line = format!("{}\n", BASE64_STANDARD.encode(self.tree.nodes[i].hash));
            let result = file.write_all(line.as_bytes());
            if result.is_err() {
            println!("Could not write fossilized tree file to location {}", tree_filename);
                return FailureReason::PathNotWriteable
            }
        }

        FailureReason::Success
    }

    // builds a Merkle inclusion proof for some leaf of the tree, complete with the required info to verify the timestamp on the blockchain.
    pub fn produce_proof(&self, index: NodeHandle) -> MerkleProof {

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
        MerkleProof { root_hash, proof_hashes, proof_directions, identifier: self.identifier.clone(), num_leaves: self.tree.num_leaves, explain_hash: self.explain_hash, block_height: self.block_height, utc_timestamp: self. utc_timestamp, tx_hash: self.tx_hash}
    }

    pub fn produce_proof_from_file(&self, filepath: &str) -> (Option<MerkleProof>, FailureReason) {
        let (result, reason) = double_hash_from_file(filepath);
        if result.is_none() {
            return (None, reason)
        }
        let starting_hash = result.unwrap();
        let index_result = self.tree.hash_lookup.get(&starting_hash);
        if index_result.is_none() {
            println!("Provided file is not in the merkle tree.");
            return (None, FailureReason::FileNotInMerkleTree);
        }
        let index: NodeHandle = *index_result.unwrap();
        (Some(self.produce_proof(index)), FailureReason::Success)
    }

    pub fn produce_proof_from_data(&self, data: &[u8]) -> (Option<MerkleProof>, FailureReason) {
        let starting_hash = double_hash(data);
        let index_result = self.tree.hash_lookup.get(&starting_hash);
        if index_result.is_none() {
            println!("Provided file is not in the merkle tree.");
            return (None, FailureReason::FileNotInMerkleTree);
        }
        let index: NodeHandle = *index_result.unwrap();
        (Some(self.produce_proof(index)), FailureReason::Success)
    }
}
