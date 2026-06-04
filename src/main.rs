pub mod tests;

use sha2::{Sha256, Digest};
use std::fmt;

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

// nodes are owned by the 'nodes' vector in the MerkleTree struct. 0 means none.
type NodeHandle = usize;

#[derive(Debug, Clone)]
struct MerkleNode {
    hash: [u8; 32],
    index: usize,
    left: NodeHandle,
    right: NodeHandle,
    parent: NodeHandle,
}

impl MerkleNode {
    fn new_leaf(hash: [u8; 32], index: usize) -> Self {
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

#[derive(Debug)]
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

#[derive(Debug)]
struct MerkleTree {
    root_index: usize,
    num_leaves: usize,
    nodes: Vec<MerkleNode>,
}

impl MerkleTree {
    fn new(data: Vec<&[u8]>) -> Self {
        let num_leaves = data.len();
        let mut nodes: Vec<MerkleNode> = vec![];
        nodes.push(MerkleNode { hash: [0u8; 32], index: 0, left: 0, right: 0, parent: 0 }); // dummy node at index 0
        for (index, d) in data.iter().enumerate() {
            nodes.push(MerkleNode::new_leaf(double_hash(d).into(), index + 1));
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

                // else if i + 1 < next_level_start {
                //     if debug {
                //         println!("border case");
                //     }
                //     let (left_side, right_side) = nodes.split_at_mut(i + 1);
                //     let mut left = &mut left_side[i];
                //     let mut right = &mut right_side[0];

                //     let parent = MerkleNode::new_internal(&mut left, &mut right, current_pointer);
                //     nodes.push(parent);
                //     if debug {
                //         MerkleTree::display_state(nodes);
                //     }
                // }
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

    fn verify_with_index(&self, data: &[u8], index: usize) -> bool {
        if index >= self.num_leaves {
            return false;
        }
        let leaf_hash = double_hash(data);
        self.nodes[index].hash == leaf_hash
    }

    fn is_a_leaf(&self, node: &MerkleNode) -> bool {
        node.index < self.num_leaves + 1 && node.index != 0
    }

    fn matches_hash(&self, node: &MerkleNode, data: &[u8]) -> bool {
        let leaf_hash = double_hash(data);
        node.hash == leaf_hash
    }

    fn verify_without_index(&self, data: &[u8]) -> bool {
        self.nodes.iter().any(|node| self.is_a_leaf(node) && self.matches_hash(node, data))
    }

    fn produce_proof(&self, index: usize) -> MerkleProof {
        let mut proof_hashes = Vec::new();
        let mut proof_directions = Vec::new();
        let mut current_index = index;
        while current_index != self.root_index {
            println!("Current index: {}, hash: {:x?}", current_index, &self.nodes[current_index].hash[..4]);
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
}


fn main() {
    let data: Vec<&[u8]> = vec![
        b"Hello, world!",
        b"Long messageeeeeeee!",
        b"short",
        b"Another message",
        b"Data 5",
        b"Data 6",
        b"Data 7",
    ];

    let merkle_tree = MerkleTree::new(data.clone());
    println!("Merkle tree has root hash: {:x?} and contains {} leaves", merkle_tree.get_root_hash(), merkle_tree.num_leaves);
    println!("Producing proof for leaf index 3 (data: {:?})", String::from_utf8_lossy(data[2]));
    let proof = merkle_tree.produce_proof(3);
    println!("Proof for leaf index 3: {}", proof);
    println!("Verifying proof: {}", merkle_tree.verify_proof(data[2], &proof));
}
