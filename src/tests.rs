#[cfg(test)]
mod tests {
    use std::fs;
    use crate::{MerkleTree, build_merkle_tree_from_directory, 
        merkle::{MerkleProof, TimestampedMerkleTree, double_hash_from_file}
    };
    use hex_literal::hex;
    use hex_fmt::HexFmt;
    use config::Config;
    extern crate rand;
    use rand::Rng;


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
            let is_valid = merkle_tree.verify(d);
            assert!(is_valid, "Data: {:?} at index {} should be valid", String::from_utf8_lossy(d), actual_index);
        }

        let invalid_data: Vec<&[u8]> = vec![
            b"invalid data",
            b"Another invalid message",
            b"shorter",
            b"Data 5.",
        ];
        for (_, d) in invalid_data.iter().enumerate() {
            assert!(!merkle_tree.verify(d), "Data: {:?} should be invalid", String::from_utf8_lossy(d));
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
        let dummy_identifier = "TESTMRKL";
        let dummy_block_height = 10;
        let dummy_tx_hash_string = "b82b914e29fb08e65e49156231b68c38c3bcb246f6a7d8ec22477478a9f1b832";
        let tx_hash = hex::decode(dummy_tx_hash_string).unwrap();
        let mut hash_bytes = vec![0u8; 32];
        hash_bytes.copy_from_slice(&tx_hash);
        let dummy_tx_hash: [u8; 32] = hash_bytes.try_into().expect("Hash length must be 32 bytes");
        let dummy_explain_hash = [0_u8; 32];
        let timestamped_tree = TimestampedMerkleTree::new(merkle_tree, dummy_identifier, dummy_block_height, dummy_tx_hash, dummy_explain_hash);
        let autoaccept = true;

        for (i, d) in data.iter().enumerate() {
            println!("testing proof for leaf index {} (data: {:?})", i + 1, String::from_utf8_lossy(d));
            let proof = timestamped_tree.produce_proof(i + 1);
            assert!(proof.verify_proof_for_data(d, autoaccept), "Proof should be valid for data: {:?}", String::from_utf8_lossy(d));
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

            // assert!(merkle_tree.verify_with_index(b"Data 50", 51), "Data 50 should be valid");
            // assert!(!merkle_tree.verify_with_index(b"Data 50", 52), "Data 50 should not be valid at index 52");
            // assert!(!merkle_tree.verify_with_index(b"Invalid data", 51), "Invalid data should not be valid at index 51");
            assert!(merkle_tree.verify(b"Data 500"), "Data 500 should be valid without index");
            assert!(!merkle_tree.verify(b"Invalid data"), "Invalid data should not be valid without index");

            for i in 0..num_leaves {
                let data_str = format!("Data {}", i);
                assert!(merkle_tree.verify(data_str.as_bytes()), "Data {} should be valid", i);
            }

            let dummy_identifier = "TESTMRKL";
            let dummy_block_height = 10;
            let dummy_tx_hash = [0_u8; 32];
            let dummy_explain_hash = [0_u8; 32];
            let timestamped_tree = TimestampedMerkleTree::new(merkle_tree, dummy_identifier, dummy_block_height, dummy_tx_hash, dummy_explain_hash);
            let autoaccept = true;

            for (i, d) in data_refs.iter().enumerate() {
                //println!("testing proof for leaf index {} (data: {:?})", i + 1, String::from_utf8_lossy(d));
                let proof = timestamped_tree.produce_proof(i + 1);
                assert!(proof.verify_proof_for_data(d, autoaccept), "Proof should be valid for data: {:?}", String::from_utf8_lossy(d));
            }
        }
    }

    #[test]
    fn build_tree_from_files() {
        let path = "testing/small_corpus";
        let merkle_tree = build_merkle_tree_from_directory(path);
        println!("Merkle tree built from directory {} has root hash: {}... and contains {} leaves", path, HexFmt(&merkle_tree.get_root_hash()[..4]), merkle_tree.num_leaves);
        merkle_tree.verify_tree();
        // index lookups commented out for now because i'm not sure i'm going to use them, and because in general we don't yet know if/how to sort the filenames.
        // assert!(merkle_tree.verify_with_index_from_file("testing/small_corpus/pg1.txt", 1), "tree should say yes to pg1.txt at index 1");
        // assert!(!merkle_tree.verify_with_index_from_file("testing/small_corpus/pg1.txt", 2), "tree should say no to pg1.txt at index 2");
        // assert!(!merkle_tree.verify_with_index_from_file("testing/small_corpus/pg2.txt", 1), "tree should say no to pg2.txt at index 1");
        assert!(merkle_tree.verify_from_file("testing/small_corpus/pg1.txt"), "tree should say yes to pg1.txt");
        assert!(merkle_tree.verify_from_file("testing/small_corpus/amber.jpg"), "tree should say yes to amber.jpg");
        assert!(merkle_tree.verify_from_file("testing/small_corpus/another_subdirectory/example_doc.docx"), "tree should say yes to amber.jpg");

        let dummy_identifier = "TESTMRKL";
        let dummy_block_height = 10;
        let dummy_tx_hash = [0_u8; 32];
        let dummy_explain_hash = [0_u8; 32];
        let timestamped_tree = TimestampedMerkleTree::new(merkle_tree, dummy_identifier, dummy_block_height, dummy_tx_hash, dummy_explain_hash);
        let autoaccept = true;

        let proof = timestamped_tree.produce_proof(1);
        //below is brittle; relies on a specific ordering of the files in the merkle tree which my code doesn't explicitly enforce. fix this later when i rethink indices
        assert!(proof.verify_proof_for_file("testing/small_corpus/pg6.txt", autoaccept), "proof should be valid for pg6.txt");
        println!("Proof for pg6.txt: {}", proof);
    }

    #[test]
    fn double_hash_match() {
        // got the following value from applying sha25sum twice to a file with contents "This is a short test file.".
        let expected_hash = hex!("788480f6d1312efdc351d804105641a8245a121a1bdcab8a7007abbc8b6ea115");

        let path = "testing/small_corpus/textfile.txt";
        let hash = crate::merkle::double_hash_from_file(path);
        println!("Double hash for {}: {}", path, HexFmt(&hash));
        assert!(hash == expected_hash, "Hash does not match expected value");
        println!("Double hash for {}: {}", path, HexFmt(&hash[..4]));

        let data = b"This is an example text file.";
        let hash = crate::merkle::double_hash(data);
        assert!(hash == expected_hash, "Hash does not match expected value");
        println!("Double hash for data: {}", HexFmt(&hash[..4]));
    }

    #[test]
    fn tree_fossilization_stability() {
        let path = "testing/small_corpus";
        let merkle_tree = build_merkle_tree_from_directory(path);
        let test_filename = "testing/custom_pg_test.txt";
        let date = "Christmas";
        merkle_tree.write_unfinished_tree_to_file(test_filename, date);
        let unfossilized_tree = MerkleTree::new_from_unfinished_tree_file(test_filename);
        assert!(merkle_tree.get_root_hash() == unfossilized_tree.get_root_hash());
        fs::remove_file(test_filename).unwrap();
    }

    #[test]
    fn proof_fossilization_stability() {
        let path = "testing/small_corpus";
        let merkle_tree = build_merkle_tree_from_directory(path);
        let temp_proof_filename = "testing/temp_proof.txt";

        let dummy_identifier = "TESTMRKL";
        let dummy_block_height = 10;
        let dummy_tx_hash = [0_u8; 32];
        let dummy_explain_hash = [0_u8; 32];
        let timestamped_tree = TimestampedMerkleTree::new(merkle_tree, dummy_identifier, dummy_block_height, dummy_tx_hash, dummy_explain_hash);

        for i in 0..timestamped_tree.tree.num_leaves {
            let proof = timestamped_tree.produce_proof(i+1);
            proof.fossilize_proof(temp_proof_filename);
            let unfossilized = MerkleProof::new_from_file(temp_proof_filename);
            assert_eq!(proof.root_hash, unfossilized.root_hash);
            let proof_length = proof.proof_hashes.len();
            assert_eq!(proof_length, unfossilized.proof_hashes.len());
            for i in 0..proof_length {
                assert_eq!(proof.proof_hashes[i], unfossilized.proof_hashes[i]);
                assert_eq!(proof.proof_directions[i], unfossilized.proof_directions[i]);
            }
        }
        fs::remove_file(temp_proof_filename).unwrap();
    }

    #[test]
    fn basic_tag() {
        let path = "testing/small_corpus";
        let merkle_tree = build_merkle_tree_from_directory(path);
        let identifier = "XMPLMRKL";
        let merkle_root_hash = merkle_tree.get_root_hash();
        println!("{}", HexFmt(merkle_root_hash));
        let num_leaves: u32 = merkle_tree.num_leaves.try_into().expect("Too many leaves to write as u32");
        let explainer_file_path = "testing/dummy_explain.txt";
        let explainer_hash = double_hash_from_file(explainer_file_path);
        let tag = crate::tag::create_chain_tag(identifier, num_leaves, merkle_root_hash, explainer_hash); 
        let expected_tag = hex!("58 4d 50 4c 4d 52 4b 4c 00 00 00 0e ba 20 ce ff 80 d2 c9 fd ac f2 31 58 40 ec 11 a5 08 1c b6 3d a1 76 f4 9a b3 f5 81 a0 7e c3 91 8e a0 e5 8f 0d df 84 5d c1 ce 07 79 33 7c 91 89 c3 0b 91 6e 7d 62 94 96 ac 85 18 ac 6b c7 50 9e 61");
        println!("{}", HexFmt(&tag));
        assert_eq!(tag, expected_tag);
    }

    #[test]
    fn verify_altered_file(){
        let path = "testing/small_corpus";
        let merkle_tree = build_merkle_tree_from_directory(path);
        let genuine_text = "testing/small_corpus/textfile.txt";
        assert!(merkle_tree.verify_from_file(genuine_text));
        // now try with an altered version I made.
        let altered_text = "testing/altered_textfile.txt";
        assert!(!merkle_tree.verify_from_file(altered_text));
    }

    #[test]
    #[ignore]
    fn authenticate_entire_corpus(){
        let test_filename = "testing/reference_timestamp/pgmerkle.txt";
        let merkle_tree = MerkleTree::new_from_unfinished_tree_file(test_filename);
        let settings = Config::builder()
                    .add_source(config::File::with_name("config"))
                    .build()
                    .unwrap();
        let path = settings.get_string("corpus_path").unwrap();
        let filepaths = crate::get_filenames_from_directory(&path);
        for filepath in filepaths{
            assert!(merkle_tree.verify_from_file(&filepath), "file at path {} did not authenticate", filepath);
        }
    }

    #[test]
    fn blockchain_tree_and_proof_verification() {
        let tree_filename = "testing/reference_timestamp/pgmerkle.txt";
        let explain_filename = "testing/reference_timestamp/canonical_pg_explain.txt";
        let incorrect_explain_filename = "testing/reference_timestamp/incorrect_explain.txt";
        let mut timestamped_tree = TimestampedMerkleTree::new_from_fossilized_tree(tree_filename);
        let autoaccept = false;
        println!("create correct tag and verify that it exists on the blockchain at the correct block height and tx hash.");
        let result = timestamped_tree.verify_timestamp(explain_filename, autoaccept);
        assert!(result);
        println!("------------");
        let badresult = timestamped_tree.verify_timestamp(incorrect_explain_filename, autoaccept);
        assert!(!badresult);
        println!("------------");
        println!("now create a few proof files, and verify them on the chain as well.");
        let explain_hash = double_hash_from_file(explain_filename);
        
        //let index = rand::thread_rng().gen_range(0..timestamped_tree.tree.num_leaves);
        for i in 1..4 {
            let index = i;
            let starting_hash = timestamped_tree.tree.nodes[index].hash;
            let proof = timestamped_tree.produce_proof(index);
            let result = proof.verify_proof(starting_hash);
            assert!(result);
        }

        let text_to_verify = "testing/pg996.txt";
        let proof = timestamped_tree.produce_proof_from_file(text_to_verify);
        let result = proof.verify_proof_for_file(text_to_verify, autoaccept);
        proof.fossilize_proof("testing/pg996_proof.txt");
        assert!(result);
    }
}