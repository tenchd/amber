use crate::merkle::double_hash;
use std::fs::File;
use base64::prelude::*;
use std::io::{Write};

pub fn csv_to_leaf_hashes(input_filepaths: Vec<&str>, output_filepath: &str) {
    let mut counter = 0;
    let mut leaf_hashes: Vec<[u8; 32]> = vec![];
    for input_filepath in input_filepaths {
        let mut reader = csv::ReaderBuilder::new().delimiter(b',').from_path(input_filepath).unwrap();
        //for _i in 0..10 {
        for record_result in reader.records() {
            //let record = reader.records().next().unwrap().unwrap();
            let record = record_result.expect("could not get next record");

            let mut components: Vec<String> = vec!["".to_string(); record.len()];
            for i in 0..record.len() {
                components[i] = "\"".to_owned() + &record.get(i).unwrap().to_string() + "\"";
            }
            let result = components.join(",");
            if counter == 0 {
                println!("{}", result);
            }
            counter = counter + 1;

            let result_hash = double_hash(result.as_bytes());
            //println!("{}", HexFmt(result_hash));
            leaf_hashes.push(result_hash);
        }

    }
    println!("done computing leaf hashes. sorting");
    leaf_hashes.sort_unstable();
    //println!("{:?}", leaf_hashes);
    println!("done sorting. writing to file");

    let mut file = File::create(output_filepath).expect("failed to create file");
    let line = format!("{}\n", leaf_hashes.len());
    file.write_all(line.as_bytes()).unwrap();

    for i in 0..leaf_hashes.len() {
        let line = format!("{}\n", BASE64_STANDARD.encode(leaf_hashes[i]));
        file.write_all(line.as_bytes()).unwrap();
    }

}