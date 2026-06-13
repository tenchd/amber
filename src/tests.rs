#[cfg(test)]
mod tests {
    use std::fs;
    use crate::{MerkleTree, build_merkle_tree_from_directory};
    use hex_literal::hex;
    use hex_fmt::HexFmt;
    use config::Config;

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
        println!("Merkle tree has root hash: {}... and contains {} leaves", HexFmt(&merkle_tree.get_root_hash()[..4]), merkle_tree.num_leaves);
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

        for (i, d) in data.iter().enumerate() {
            println!("testing proof for leaf index {} (data: {:?})", i + 1, String::from_utf8_lossy(d));
            let proof = merkle_tree.produce_proof(i + 1);
            assert!(proof.verify_proof_for_data(d, merkle_tree.get_root_hash()), "Proof should be valid for data: {:?}", String::from_utf8_lossy(d));
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
            println!("Merkle tree has root hash: {:x?}... and contains {} leaves", HexFmt(&merkle_tree.get_root_hash()[..4]), merkle_tree.num_leaves);
            merkle_tree.verify_tree();

            assert!(merkle_tree.verify_with_index(b"Data 50", 51), "Data 50 should be valid");
            assert!(!merkle_tree.verify_with_index(b"Data 50", 52), "Data 50 should not be valid at index 52");
            assert!(!merkle_tree.verify_with_index(b"Invalid data", 51), "Invalid data should not be valid at index 51");
            assert!(merkle_tree.verify_without_index(b"Data 500"), "Data 500 should be valid without index");
            assert!(!merkle_tree.verify_without_index(b"Invalid data"), "Invalid data should not be valid without index");

            for i in 0..num_leaves {
                let data_str = format!("Data {}", i);
                assert!(merkle_tree.verify_without_index(data_str.as_bytes()), "Data {} should be valid", i);
            }

            for (i, d) in data_refs.iter().enumerate() {
                //println!("testing proof for leaf index {} (data: {:?})", i + 1, String::from_utf8_lossy(d));
                let proof = merkle_tree.produce_proof(i + 1);
                assert!(proof.verify_proof_for_data(d, merkle_tree.get_root_hash()), "Proof should be valid for data: {:?}", String::from_utf8_lossy(d));
            }
        }
    }

    #[test]
    fn build_tree_from_files() {
        let path = "testing/small_corpus";
        let merkle_tree = build_merkle_tree_from_directory(path);
        println!("Merkle tree built from directory {} has root hash: {}... and contains {} leaves", path, HexFmt(&merkle_tree.get_root_hash()[..4]), merkle_tree.num_leaves);
        merkle_tree.verify_tree();
        assert!(merkle_tree.verify_with_index_from_file("testing/small_corpus/pg1.txt", 1), "tree should say yes to pg1.txt at index 1");
        assert!(!merkle_tree.verify_with_index_from_file("testing/small_corpus/pg1.txt", 2), "tree should say no to pg1.txt at index 2");
        assert!(!merkle_tree.verify_with_index_from_file("testing/small_corpus/pg2.txt", 1), "tree should say no to pg2.txt at index 1");
        assert!(merkle_tree.verify_without_index_from_file("testing/small_corpus/pg1.txt"), "tree should say yes to pg1.txt");
        assert!(!merkle_tree.verify_without_index_from_file("testing/small_corpus/ignore.txt"), "tree should say no to file not in Merkle tree");
        let proof = merkle_tree.produce_proof(1);
        assert!(proof.verify_proof_for_file("testing/small_corpus/pg1.txt", merkle_tree.get_root_hash()), "proof should be valid for pg1.txt.txt");
        println!("Proof for pg1.txt: {}", proof);
    }

    #[test]
    fn double_hash_match() {
        // got the following value from applying sha25sum twice to a file with contents "This is a short test file.".
        let expected_hash = hex!("80b621c7642162e6cb9c342ad2c0a900867175c664a292eb0ad311e9ca92f23e");

        let path = "testing/small_corpus/ignore.txt";
        let hash = crate::merkle::double_hash_from_file(path);
        assert!(hash == expected_hash, "Hash does not match expected value");
        println!("Double hash for {}: {}", path, HexFmt(&hash[..4]));

        let data = b"This is a short test file.";
        let hash = crate::merkle::double_hash(data);
        assert!(hash == expected_hash, "Hash does not match expected value");
        println!("Double hash for data: {}", HexFmt(&hash[..4]));

        let new_path = "testing/dummy_explain.txt";
        let new_hash = crate::merkle::double_hash_from_file(new_path);
        println!("Hash of dummy doc: {}", HexFmt(new_hash));
    }

    #[test]
    fn fossilization_stability() {
        let path = "testing/small_corpus";
        let merkle_tree = build_merkle_tree_from_directory(path);
        let test_filename = "testing/custom_pg_test.txt";
        let date = "Christmas";
        merkle_tree.fossilize_tree(test_filename, date);
        let unfossilized_tree = MerkleTree::new_from_fossilized_tree(test_filename);
        assert!(merkle_tree.get_root_hash() == unfossilized_tree.get_root_hash());
        fs::remove_file(test_filename).unwrap();
    }

    #[test]
    fn basic_tag() {
        let path = "testing/small_corpus";
        let merkle_tree = build_merkle_tree_from_directory(path);
        let identifier = "PGMERKLE";
        let merkle_root_hash = merkle_tree.get_root_hash();
        let num_leaves: u32 = merkle_tree.num_leaves.try_into().expect("Too many leaves to write as u32");
        let explainer_file_path = "testing/dummy_explain.txt";
        let tag = crate::tag::create_chain_tag(identifier, num_leaves, merkle_root_hash, explainer_file_path); 
        let expected_tag = hex!("50 47 4d 45 52 4b 4c 45 00 00 00 0a 44 5a 1c 4e 49 fc b2 e4 db 00 0c 95 6e 50 f0 38 43 eb 56 7a 32 e0 ce 54 1e 5f dd 08 d6 26 4b ae a0 e5 8f 0d df 84 5d c1 ce 07 79 33 7c 91 89 c3 0b 91 6e 7d 62 94 96 ac 85 18 ac 6b c7 50 9e 61");
        assert_eq!(tag, expected_tag);
    }

    #[test]
    #[ignore]
    fn full_pg_test() {
        let settings = Config::builder()
                    .add_source(config::File::with_name("config"))
                    .build()
                    .unwrap();
        let path = settings.get_string("corpus_path").unwrap();
        let merkle_tree = build_merkle_tree_from_directory(&path);
        println!("Merkle tree built from directory {} has root hash: {}... and contains {} leaves", path, HexFmt(&merkle_tree.get_root_hash()[..4]), merkle_tree.num_leaves);
        merkle_tree.verify_tree();
        println!("Tree verified.");
    }
}