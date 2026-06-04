pub mod tests;

use sha2::{Sha256, Digest};


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
        let hash = double_hash(&[left.hash, right.hash].concat());
        let new_node = MerkleNode { hash, index, left: 0, right: 0, parent: 0 };
        left.parent = index;
        right.parent = index;
        new_node
    }

    fn new_internal_end(left: &mut MerkleNode, index: usize) -> Self {
        let hash = double_hash(&[left.hash, left.hash].concat());
        let new_node = MerkleNode { hash, index, left: 0, right: 0, parent: 0 };
        left.parent = index;
        new_node
    }
}

#[derive(Debug)]
struct MerkleProof {
    leaf_index: usize,
    proof_hashes: Vec<[u8; 32]>,
    proof_directions: Vec<bool>, // true for left, false for right
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
        for (index, d) in data.iter().enumerate() {
            nodes.push(MerkleNode::new_leaf(double_hash(d).into(), index));
        }
        let root_index = MerkleTree::build_tree(&mut nodes, num_leaves);
        MerkleTree { root_index, num_leaves, nodes }
    }

    fn build_tree(nodes: &mut Vec<MerkleNode>, num_leaves: usize) -> usize {
        let mut current_level_start = 1;
        let mut next_level_start: usize = num_leaves + 1;
        let mut current_pointer = num_leaves + 1;

        while current_level_start + 1 < next_level_start {
            for i in (current_level_start..next_level_start).step_by(2) {
                if i +2 < next_level_start {
                    let (left_side, right_side) = nodes.split_at_mut(i + 1);
                    let mut left = &mut left_side[i];
                    let mut right = &mut right_side[0];
                    let parent = MerkleNode::new_internal(&mut left, &mut right, current_pointer);
                    nodes.push(parent);
                }

                if i + 1 < next_level_start {
                    let (left_side, right_side) = nodes.split_at_mut(i);
                    let mut left = &mut left_side[i-1];
                    let mut right = &mut right_side[0];
                    let parent = MerkleNode::new_internal(&mut left, &mut right, current_pointer);
                    nodes.push(parent);
                }
                else {
                    let mut left = &mut nodes[i];
                    let parent = MerkleNode::new_internal_end(&mut left, current_pointer);
                    nodes.push(parent);
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

    fn verify_without_index(&self, data: &[u8]) -> bool {
        let leaf_hash = double_hash(data);
        self.nodes.iter().any(|node| node.index < self.num_leaves && node.hash == leaf_hash)
    }

    fn produce_proof(&self, index: usize) -> MerkleProof {
        let mut proof_hashes = Vec::new();
        let mut proof_directions = Vec::new();
        let mut current_index = index;
        while current_index != self.root_index {
            println!("Current index: {}, hash: {:x?}", current_index, self.nodes[current_index].hash);
            let parent_index = self.nodes[current_index].parent;
            let sibling_index = if self.nodes[parent_index].left == current_index {
                self.nodes[parent_index].right
            } else {
                self.nodes[parent_index].left
            };
            proof_hashes.push(self.nodes[sibling_index].hash);
            proof_directions.push(self.nodes[parent_index].left == current_index);
            current_index = parent_index;
        }
        MerkleProof { leaf_index: index, proof_hashes, proof_directions }
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
    
    println!("{}", merkle_tree.nodes[0].index);
}
