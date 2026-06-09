use crate::double_hash_from_file;
// Creates the 76-byte tag that will be written to the blockchain.
pub fn create_chain_tag(identifier: &str, num_merkle_leaves: u32, merkle_root_hash: [u8; 32], explainer_file_path: &str) -> Vec<u8> {
    assert!(identifier.is_ascii(), "Identifier must be ascii characters only.");
    assert!(identifier.len() == 8, "Identifier must have exactly 8 characters. You supplied {}", identifier.len());

    let num_merkle_leaves_as_bytes: [u8; 4] = num_merkle_leaves.to_be_bytes();

    let explainer_hash = double_hash_from_file(explainer_file_path);

    let result = [identifier.as_bytes(), &num_merkle_leaves_as_bytes, &merkle_root_hash, &explainer_hash].concat();
    assert!(result.len() == 76, "Result should have 76 bytes. You had {}", result.len());
    //println!("Wrote identifier {}, # merkle leaves {}, merkle root hash {:x?}, and explainer hash {:x?} to bytes.\n
    //Result: {:x?}", identifier, num_merkle_leaves, merkle_root_hash, explainer_hash, result);
    result
}


