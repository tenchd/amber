

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

        for i in 0..merkle_tree.nodes.len() {
            let node = &merkle_tree.nodes[i];
            assert!(node.index == i, "Node index mismatch at node {}: expected {}, got {}", i, i, node.index);
        }

        for (i, d) in data.iter().enumerate() {
            let actual_index = i + 1;
            let is_valid = merkle_tree.verify_without_index(d);
            assert!(is_valid, "Data: {:?} at index {} should be valid", String::from_utf8_lossy(d), actual_index);
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

    #[test]
    fn test_verify_proof() {
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

        // let test_data = b"Data 7";
        // let test_index = 7;
        // let proof = merkle_tree.produce_proof(test_index);
        // println!("Proof for leaf index {}: {}", test_index, proof);
        // assert!(merkle_tree.verify_proof(test_data, &proof), "Proof should be valid for data: {:?}", String::from_utf8_lossy(test_data));

        for (i, d) in data.iter().enumerate() {
            println!("testing proof for leaf index {} (data: {:?})", i + 1, String::from_utf8_lossy(d));
            let proof = merkle_tree.produce_proof(i + 1);
            assert!(merkle_tree.verify_proof(d, &proof), "Proof should be valid for data: {:?}", String::from_utf8_lossy(d));
        }
    }

    #[test]
    fn stress_test() {
        for num_leaves in [1000, 5983, 10985,
         109484,
         ] {
            println!("Testing with {} leaves", num_leaves);
            let data: Vec<Vec<u8>> = (0..num_leaves).map(|i| format!("Data {}", i).into_bytes()).collect();
            let data_refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
            let merkle_tree = MerkleTree::new(data_refs.clone());
            println!("Merkle tree has root hash: {:x?} and contains {} leaves", merkle_tree.get_root_hash(), merkle_tree.num_leaves);

            assert!(merkle_tree.verify_with_index(b"Data 50", 51), "Data 50 should be valid");
            assert!(!merkle_tree.verify_with_index(b"Data 50", 52), "Data 50 should not be valid at index 52");
            assert!(!merkle_tree.verify_with_index(b"Invalid data", 51), "Invalid data should not be valid at index 51");
            assert!(merkle_tree.verify_without_index(b"Data 500"), "Data 500 should be valid without index");
            assert!(!merkle_tree.verify_without_index(b"Invalid data"), "Invalid data should not be valid without index");

            for i in 0..num_leaves {
                let data_str = format!("Data {}", i);
                assert!(merkle_tree.verify_with_index(data_str.as_bytes(), i + 1), "Data {} should be valid at index {}", i, i + 1);
            }

            for (i, d) in data_refs.iter().enumerate() {
                //println!("testing proof for leaf index {} (data: {:?})", i + 1, String::from_utf8_lossy(d));
                let proof = merkle_tree.produce_proof(i + 1);
                assert!(merkle_tree.verify_proof(d, &proof), "Proof should be valid for data: {:?}", String::from_utf8_lossy(d));
            }
        }
    }
}