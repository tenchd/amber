use std::fs::{File, read_to_string};
use std::io::{Write};
use std::process::Command;
use hex_fmt::HexFmt;
use config::Config;
use crate::merkle::double_hash_from_file;

// Create the identifier, num_leaves, and root hash part of the tag that will be written to the blockchain.
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
    //println!("Wrote identifier {},\n# merkle leaves {},\nmerkle root hash {},\nand explainer hash {}\nto bytes.\n
    //Result: {}\n", identifier, num_merkle_leaves, HexFmt(merkle_root_hash), HexFmt(explainer_hash), HexFmt(&result));
    result
}

// Inserts relevant details about the merkle tree, target block, day & time, etc. into the explanatory document and writes the document as a txt file.
pub fn write_document(output_filename: &str, date: &str, time: &str, block_lockout: usize, identifier: &str, num_merkle_leaves: u32, merkle_root_hash: [u8; 32]) {
    let mut pieces: Vec<String> = vec![];
    let line1 = format!("On {}, at roughly {} UTC, I built a Merkle tree from the raw text files of the works listed on Project Gutenberg (PG) and wrote the root hash of this Merkle tree to the Bitcoin blockchain in block {}, or one of several blocks immediately following.\n", date, time, block_lockout);
    pieces.push(line1);
    let line2 = read_to_string("src/static_piece1.txt").expect("couldn't find first static piece");
    pieces.push(line2);
    let tag_prefix = create_chain_tag_prefix(identifier, num_merkle_leaves, merkle_root_hash);
    let line3 = format!("- {} in ascii (8 bytes): {}
- 4 bytes representing the number of leaves in the Merkle tree ({}) as an unsigned integer: {}
- the Merkle tree root hash (32 bytes) {}
- the SHA256 double hash of this document 

So the message written out is 
{} 
followed by the 32 byte double SHA256 hash of this document.

I set a locktime to my transaction of block {} and provided a high transaction fee. Hopefully this will result in the transaction being mined in block {}, but if not it should appear in one of the next few blocks mined. It's not possible to be sure a priori which block it will end up in due to the way Bitcoin mining works.

Verification
Let's say you have this document, a file containing the Merkle tree, and some text files. You would like to make sure that the text files were part of the PG corpus in 2026.
First, you must verify that this document and the Merkle tree are valid. To do this, first verify that there is a transaction on the Bitcoin blockchain in block {} or shortly thereafter containing the message described above. The Merkle tree root hash in the blockchain message should exactly match the root hash written in this file, and the SHA256 double hash of this document should match exactly as well. Further, the Merkle tree should be valid (meaning the hash relationships between nodes are correct) and the root hash should match the one written in this file. The Merkle tree should have {} leaves.\n", identifier, HexFmt(identifier.as_bytes()),
                                                                                    num_merkle_leaves, HexFmt(num_merkle_leaves.to_be_bytes()),
                                                                                    HexFmt(merkle_root_hash),
                                                                                    HexFmt(tag_prefix),
                                                                                    block_lockout, block_lockout,
                                                                                    block_lockout, num_merkle_leaves);
    pieces.push(line3);
    let line4 = read_to_string("src/static_piece2.txt").expect("couldn't find second static piece");
    pieces.push(line4);

    let mut file = File::create(output_filename).expect("failed to create file");
    for piece in pieces {
        file.write_all(&piece.into_bytes()).expect("couldn't write line");
    }

    let settings = Config::builder()
                    .add_source(config::File::with_name("config"))
                    .build()
                    .unwrap();

    let private_key_path = settings.get_string("private_key_path").unwrap();
    let public_key_path = settings.get_string("public_key_path").unwrap();
    let merkle_root_hash_string = format!("{}", HexFmt(merkle_root_hash));

    let sh_output = Command::new("sh")
                                .arg("sign.sh")
                                .arg(private_key_path)
                                .arg(public_key_path)
                                .arg(merkle_root_hash_string)
                                .arg(date)
                                .arg(output_filename)
                                .output()
                                .expect("failed to execute process");
    println!("Outcome of signing with private key: {}", String::from_utf8(sh_output.stdout).unwrap());
}

// Inserts relevant details about the merkle tree, target block, day & time, etc. into the explanatory document and writes the document as a txt file.
// pub fn write_document(output_filename: &str, date: &str, time: &str, block_lockout: usize, identifier: &str, num_merkle_leaves: u32, merkle_root_hash: [u8; 32]) {
//     let template = read_to_string("explain_template.txt").expect("could not read template text file");
//     //let line1 = format!("On {}, at roughly {} UTC, I built a Merkle tree from the raw text files of the works listed on Project Gutenberg (PG) and wrote the root hash of this Merkle tree to the Bitcoin blockchain in block {}, or one of several blocks immediately following.\n", date, time, block_lockout);
    
//     let tag_prefix = create_chain_tag_prefix(identifier, num_merkle_leaves, merkle_root_hash);

//     let filled_in_template = format!(template, 
//                                                 date, time, block_lockout,
//                                                 identifier, HexFmt(identifier.as_bytes()),
//                                                 num_merkle_leaves, HexFmt(num_merkle_leaves.to_be_bytes()),
//                                                 HexFmt(merkle_root_hash),
//                                                 HexFmt(tag_prefix),
//                                                 block_lockout, block_lockout,
//                                                 block_lockout, num_merkle_leaves);
//     let line3 = format!("- {} in ascii (8 bytes): {}
// - 4 bytes representing the number of leaves in the Merkle tree ({}) as an unsigned integer: {}
// - the Merkle tree root hash (32 bytes) {}
// - the SHA256 double hash of this document 

// So the message written out is 
// {} 
// followed by the 32 byte double SHA256 hash of this document.

// I set a lockout to my transaction of block {} and provided a high transaction fee. Hopefully this will result in the transaction being mined in block {}, but if not it should appear in one of the next few blocks mined. It's not possible to be sure a priori which block it will end up in due to the way Bitcoin mining works.

// Verification
// Let's say you have this document, a file containing the Merkle tree, and some text files. You would like to make sure that the text files were part of the PG corpus in 2026.
// First, you must verify that this document and the Merkle tree are valid. To do this, first verify that there is a transation on the Bitcoin blockchain in block {} or shortly thereafter containing the message described above. The Merkle tree root hash in the blockchain message should exactly match the root hash written in this file, and the SHA256 double hash of this document should match exactly as well. Further, the Merkle tree should be valid (meaning the hash relationships between nodes are correct) and the root hash should match the one written in this file. The Merkle tree should have {} leaves.\n", identifier, HexFmt(identifier.as_bytes()),
//                                                                                     num_merkle_leaves, HexFmt(num_merkle_leaves.to_be_bytes()),
//                                                                                     HexFmt(merkle_root_hash),
//                                                                                     HexFmt(tag_prefix),
//                                                                                     block_lockout, block_lockout,
//                                                                                     block_lockout, num_merkle_leaves);


//     let mut file = File::create(output_filename).expect("failed to create file");
//     for piece in pieces {
//         file.write_all(&piece.into_bytes()).expect("couldn't write line");
//     }

//     let settings = Config::builder()
//                     .add_source(config::File::with_name("config"))
//                     .build()
//                     .unwrap();

//     let private_key_path = settings.get_string("private_key_path").unwrap();
//     let public_key_path = settings.get_string("public_key_path").unwrap();
//     let merkle_root_hash_string = format!("{}", HexFmt(merkle_root_hash));

//     let sh_output = Command::new("sh")
//                                 .arg("sign.sh")
//                                 .arg(private_key_path)
//                                 .arg(public_key_path)
//                                 .arg(merkle_root_hash_string)
//                                 .arg(date)
//                                 .arg(output_filename)
//                                 .output()
//                                 .expect("failed to execute process");
//     println!("Outcome of signing with private key: {}", String::from_utf8(sh_output.stdout).unwrap());
// }