use std::fs::{File, read_to_string};
use std::io::{Write,Read};
use hex_fmt::HexFmt;

use crate::double_hash_from_file;
pub fn create_chain_tag_prefix(identifier: &str, num_merkle_leaves: u32, merkle_root_hash: [u8; 32]) -> Vec<u8> {
    assert!(identifier.is_ascii(), "Identifier must be ascii characters only.");
    assert!(identifier.len() == 8, "Identifier must have exactly 8 characters. You supplied {}", identifier.len());

    let num_merkle_leaves_as_bytes: [u8; 4] = num_merkle_leaves.to_be_bytes();
    let result = [identifier.as_bytes(), &num_merkle_leaves_as_bytes, &merkle_root_hash].concat();
    result
}

// Creates the 76-byte tag that will be written to the blockchain.
pub fn create_chain_tag(identifier: &str, num_merkle_leaves: u32, merkle_root_hash: [u8; 32], explainer_file_path: &str) -> Vec<u8> {
    let prefix = create_chain_tag_prefix(identifier, num_merkle_leaves, merkle_root_hash);

    let explainer_hash = double_hash_from_file(explainer_file_path);

    let result = [prefix, explainer_hash.to_vec()].concat();
    assert!(result.len() == 76, "Result should have 76 bytes. You had {}", result.len());
    println!("Wrote identifier {}, # merkle leaves {}, merkle root hash {:x?}, and explainer hash {:x?} to bytes.\n
    Result: {:x?}", identifier, num_merkle_leaves, merkle_root_hash, explainer_hash, result);
    result
}

pub fn write_document(output_filename: &str, day: &str, time: &str, block_lockout: usize, identifier: &str, num_merkle_leaves: u32, merkle_root_hash: [u8; 32]) {
    let mut pieces: Vec<String> = vec![];
    let line1 = format!("On June {}, 2026, at roughly {} UTC, I built a merkle tree from the raw text files of the works listed on Project Gutenberg and wrote the root hash of this merge tree to the Bitcoin blockchain in block {}, or one of several blocks immediately following.\n", day, time, block_lockout);
    pieces.push(line1);
    let line2 = read_to_string("src/static_piece1.txt").expect("couldn't find first static piece");
    pieces.push(line2);
    let tag_prefix = create_chain_tag_prefix(identifier, num_merkle_leaves, merkle_root_hash);
    let line3 = format!("- {} in ascii (8 bytes): {}
- 4 bytes representing the number of leaves in the merkle tree ({}) as an unsigned integer: {}
- the merkle tree root hash (32 bytes) {}
- the SHA256 double hash of this document 

So the message written out is 
{} 
followed by the 32 byte double SHA256 hash of this document.

I set a lockout to my transaction of block {} and provided a high transaction fee. Hopefully this will result in the transaction being mined in block {}, but if not it should appear in one of the next few blocks mined. It's not possible to be sure a priori which block it will end up in due to the way Bitcoin mining works.

Verification
First, you must verify that this document and the accompanying Merkle tree are valid. To do this, first verify that there is a transation on the Bitcoin blockchain in block {} or shortly thereafter containing the message described above. The merkle tree root hash should exactly match the one written in this file, and the SHA256 double hash of this document should match exactly as well. The merkle tree should be valid (meaning the hash relationships between nodes are correct) and the root hash should match the one written in this file. The merkle tree should have {} leaves.\n", identifier, HexFmt(identifier.as_bytes()),
                                                                                    num_merkle_leaves, HexFmt(num_merkle_leaves.to_be_bytes()),
                                                                                    HexFmt(merkle_root_hash),
                                                                                    HexFmt(tag_prefix),
                                                                                    block_lockout, block_lockout,
                                                                                    block_lockout, num_merkle_leaves);
    pieces.push(line3);
    let line4 = read_to_string("src/static_piece2.txt").expect("couldn't find second static piece");
    pieces.push(line4);

    let mut file = File::create(output_filename).expect("filed to create file");
    for piece in pieces {
        file.write_all(&piece.into_bytes()).expect("couldn't write line");
    }
}

