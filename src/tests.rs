

#[cfg(test)]
mod tests {
use crate::{MerkleTree};

    #[test]
    fn basic_test() {
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
        for (i, d) in data.iter().enumerate() {
            let is_valid = merkle_tree.verify_with_index(d, i);
            assert!(is_valid, "Data: {:?} at index {} should be valid", String::from_utf8_lossy(d), i);
        }

        let invalid_data: Vec<&[u8]> = vec![
            b"invalid data",
            b"Another invalid message",
            b"shorter",
            b"Data 5.",
        ];
        for (_, d) in invalid_data.iter().enumerate() {
            assert!(!merkle_tree.verify_without_index(d), "Data: {:?} should be invalid", String::from_utf8_lossy(d));
        }
    }
}