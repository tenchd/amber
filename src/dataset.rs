use crate::merkle::double_hash;
use std::fs::File;
use base64::prelude::*;
use std::io::{Write};

pub fn csv_to_leaf_hashes(input_filepath: &str, output_filepath: &str) {
    let mut reader = csv::ReaderBuilder::new().delimiter(b',').from_path(input_filepath).unwrap();
    let mut leaf_hashes: Vec<[u8; 32]> = vec![];
    //for _i in 0..10 {
    let mut first = true;
    for record_result in reader.records() {
        //let record = reader.records().next().unwrap().unwrap();
        let record = record_result.expect("could not get next record");
        //println!("{:?}", record);

        let mut components: Vec<String> = vec!["".to_string(); record.len()];
        for i in 0..record.len() {
            components[i] = "\"".to_owned() + &record.get(i).unwrap().to_string() + "\"";
        }
        let result = components.join(",");
        if first {
            println!("{}", result);
            first = false;
        }
        let result_hash = double_hash(result.as_bytes());
        //println!("{}", HexFmt(result_hash));
        leaf_hashes.push(result_hash);
    }
    //println!("{:?}", leaf_hashes);

    let mut file = File::create(output_filepath).expect("failed to create file");
    let line = format!("{}\n", leaf_hashes.len());
    file.write_all(line.as_bytes()).unwrap();

    for i in 0..leaf_hashes.len() {
        let line = format!("{}\n", BASE64_STANDARD.encode(leaf_hashes[i]));
        file.write_all(line.as_bytes()).unwrap();
    }

}