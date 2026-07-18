use std::fs::{File, read_to_string};
use std::io::{Write};
use std::process::Command;
use hex_fmt::HexFmt;
use config::Config;
use text_template::Template;
use std::collections::HashMap;

// Create the identifier, num_leaves, and root hash part of the tag that will be written to the blockchain.
pub fn create_chain_tag_prefix(identifier: &str, num_merkle_leaves: u32, merkle_root_hash: [u8; 32]) -> Vec<u8> {
    assert!(identifier.is_ascii(), "Identifier must be ascii characters only.");
    assert!(identifier.len() == 8, "Identifier must have exactly 8 characters. You supplied {}", identifier.len());

    let num_merkle_leaves_as_bytes: [u8; 4] = num_merkle_leaves.to_be_bytes();
    let result = [identifier.as_bytes(), &num_merkle_leaves_as_bytes, &merkle_root_hash].concat();
    result
}

// Creates the 76-byte tag that will be written to the blockchain.
pub fn create_chain_tag(identifier: &str, num_merkle_leaves: u32, merkle_root_hash: [u8; 32], explainer_hash: [u8; 32]) -> Vec<u8> {
    let prefix = create_chain_tag_prefix(identifier, num_merkle_leaves, merkle_root_hash);

    //let explainer_hash = double_hash_from_file(explainer_file_path);

    let result = [prefix, explainer_hash.to_vec()].concat();
    assert!(result.len() == 76, "Result should have 76 bytes. You had {}", result.len());
    //println!("Wrote identifier {},\n# merkle leaves {},\nmerkle root hash {},\nand explainer hash {}\nto bytes.\n
    //Result: {}\n", identifier, num_merkle_leaves, HexFmt(merkle_root_hash), HexFmt(explainer_hash), HexFmt(&result));
    result
}

// Inserts relevant details about the merkle tree, target block, day & time, etc. into the explanatory document and writes the document as a txt file.
pub fn write_document(output_filename: &str, date: &str, time: &str, locktime: usize, identifier: &str, num_merkle_leaves: u32, merkle_root_hash: [u8; 32]) {
    let explain_template_filepath = "templates/explain_template.txt";
    let template_string = read_to_string(explain_template_filepath).unwrap();
    let template = Template::from(template_string.as_str());

    let mut values: HashMap<&str, &str> = HashMap::new();
    values.insert("date",date);
    values.insert("time",time);
    let binding = locktime.to_string();
    let locktime = (&binding).as_str();
    values.insert("locktime",locktime);
    values.insert("identifier",identifier);
    let hex_identifier_string = format!("{}", HexFmt(identifier.as_bytes()));
    values.insert("identifier_hex", hex_identifier_string.as_str());
    let num_merkle_leaves_string = num_merkle_leaves.to_string();
    values.insert("num_merkle_leaves",&num_merkle_leaves_string.as_str());
    let hex_leaves_string = format!("{}", HexFmt(num_merkle_leaves.to_be_bytes()));
    values.insert("num_merkle_leaves_hex",&hex_leaves_string.as_str());
    let root_hash_hex_string = format!("{}", HexFmt(merkle_root_hash));
    values.insert("merkle_root_hash", root_hash_hex_string.as_str());

    let tag_prefix = create_chain_tag_prefix(identifier, num_merkle_leaves, merkle_root_hash);
    let hex_tag_prefix_string = format!("{}", HexFmt(tag_prefix));
    values.insert("tag_prefix", &hex_tag_prefix_string.as_str());

    let text = template.try_fill_in(&values).unwrap().to_string();

    let mut file = File::create(output_filename).expect("failed to create file");
    file.write_all(&text.into_bytes()).expect("couldn't write file");

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