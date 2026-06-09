

#[cfg(test)]
mod tests {

use crate::{MerkleTree, build_merkle_tree_from_directory};
use hex_literal::hex;

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
        let merkle_tree = MerkleTree::new_from_data(data.clone());
        println!("Merkle tree has root hash: {:x?} and contains {} leaves", merkle_tree.get_root_hash(), merkle_tree.num_leaves);
        merkle_tree.verify_tree();

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
        let merkle_tree = MerkleTree::new_from_data(data.clone());
        merkle_tree.verify_tree();

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
            let merkle_tree = MerkleTree::new_from_data(data_refs.clone());
            println!("Merkle tree has root hash: {:x?} and contains {} leaves", merkle_tree.get_root_hash(), merkle_tree.num_leaves);
            merkle_tree.verify_tree();

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

    #[test]
    fn build_tree_from_files() {
        let path = "../small_merkel";
        let merkle_tree = build_merkle_tree_from_directory(path);
        println!("Merkle tree built from directory {} has root hash: {:x?} and contains {} leaves", path, &merkle_tree.get_root_hash()[..4], merkle_tree.num_leaves);
        merkle_tree.verify_tree();
        assert!(merkle_tree.verify_with_index_from_file("../small_merkel/PG11_raw.txt", 1), "tree should say yes to PG11_raw.txt at index 1");
        assert!(!merkle_tree.verify_with_index_from_file("../small_merkel/PG11_raw.txt", 2), "tree should say no to PG11_raw.txt at index 2");
        assert!(!merkle_tree.verify_with_index_from_file("../small_merkel/PG50_raw.txt", 1), "tree should say no to PG50_raw.txt at index 1");
        assert!(merkle_tree.verify_without_index_from_file("../small_merkel/PG11_raw.txt"), "tree should say yes to PG11_raw.txt without index");
        assert!(!merkle_tree.verify_without_index_from_file("../gutenberg/data/raw/PG109_raw.txt"), "tree should say no to PG109_raw.txt without index");
        let proof = merkle_tree.produce_proof(1);
        assert!(merkle_tree.verify_proof_from_file("../small_merkel/PG11_raw.txt", &proof), "proof should be valid for PG11_raw.txt");
        println!("Proof for PG11_raw.txt: {}", proof);
    }

    #[test]
    fn double_hash_match() {
        // got the following value from applying sha25sum twice to a file with contents "This is a short test file.".
        let expected_hash = hex!("80b621c7642162e6cb9c342ad2c0a900867175c664a292eb0ad311e9ca92f23e");

        let path = "../small_merkel/test.txt";
        let hash = crate::double_hash_from_file(path);
        assert!(hash == expected_hash, "Hash does not match expected value");
        println!("Double hash for {}: {:x?}", path, &hash[..4]);

        let data = b"This is a short test file.";
        let hash = crate::double_hash(data);
        assert!(hash == expected_hash, "Hash does not match expected value");
        println!("Double hash for data: {:x?}", &hash[..4]);
    }

    #[test]
    fn basic_serialization() {
        let path = "../small_merkel";
        let merkle_tree = build_merkle_tree_from_directory(path);
        let original_root_hash = merkle_tree.get_root_hash();
        //println!("Merkle tree built from directory {} has root hash: {:x?} and contains {} leaves", path, &merkle_tree.get_root_hash()[..4], merkle_tree.num_leaves);
        let serialized = serde_json::to_string(&merkle_tree).unwrap();
        //println!("Serialized Merkle tree: {}", serialized);
        let deserialized: MerkleTree = serde_json::from_str(&serialized).unwrap();
        //println!("Deserialized Merkle tree has root hash: {:x?} and contains {} leaves", &deserialized.get_root_hash()[..4], deserialized.num_leaves);
        assert!(deserialized.get_root_hash() == original_root_hash);
        deserialized.verify_tree();
        println!("Deserialized tree verified.");
    }

    #[test]
    fn basic_tag() {
        let path = "../small_merkel";
        let merkle_tree = build_merkle_tree_from_directory(path);
        let identifier = "PGMERKLE";
        let merkle_root_hash = merkle_tree.get_root_hash();
        let num_leaves: u32 = merkle_tree.num_leaves.try_into().expect("Too many leaves to write as u32");
        let explainer_file_path = "dummy_explain.txt";
        let tag = crate::tag::create_chain_tag(identifier, num_leaves, merkle_root_hash, explainer_file_path); 
        let expected_tag = hex!("50 47 4d 45 52 4b 4c 45 00 00 00 0c ce 90 85 b9 6a a4 7f d9 6f 57 72 e0 f6 d7 9b 56 a9 27 89 af aa 27 1c 30 d7 41 b2 c9 9a 36 60 ab a0 e5 8f 0d df 84 5d c1 ce 07 79 33 7c 91 89 c3 0b 91 6e 7d 62 94 96 ac 85 18 ac 6b c7 50 9e 61");
        assert_eq!(tag, expected_tag);
    }
}