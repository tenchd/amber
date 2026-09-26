use crate::merkle::double_hash;
use std::fs::File;
use base64::prelude::*;
use csv::StringRecord;
use std::io::{Write};
use std::path::PathBuf;

fn record_to_string(record: &csv::StringRecord) -> String {
    let mut components: Vec<String> = vec!["".to_string(); record.len()];
    for i in 0..record.len() {
        components[i] = "\"".to_owned() + &record.get(i).unwrap().to_string() + "\"";
    }
    let result = components.join(",");
    result
}

fn write_csv_line_to_file(line: String, counter: i32, directory: &mut PathBuf){
    directory.push(format!("{}.txt", counter));
    let mut output = File::create(&directory).unwrap();
    directory.pop();
    write!(output, "{}", line).expect("could not write csv line to new file");
}

pub fn csv_to_leaf_hashes(input_filepaths: Vec<&str>, output_filepath: &str) {
    let mut counter = 0;
    let mut leaf_hashes: Vec<[u8; 32]> = vec![];
    for input_filepath in input_filepaths {
        let mut reader = csv::ReaderBuilder::new().delimiter(b',').from_path(input_filepath).unwrap();
        //for _i in 0..10 {
        for record_result in reader.records() {
            let record = record_result.expect("could not get next record");
            let result = record_to_string(&record);
            // if counter == 0 {
            //     println!("{}", result);
            // }
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

pub fn csv_to_directory(input_filepath: &str, output_filepath: &str) {
    let mut counter = 0;
    let mut reader = csv::ReaderBuilder::new().delimiter(b',').from_path(input_filepath).unwrap();
    let mut path: PathBuf = PathBuf::new();
    path.push(output_filepath);
    let header = record_to_string(reader.headers().unwrap());
    write_csv_line_to_file(header, 0, &mut path);
    for record_result in reader.records() {
        let record = record_result.expect("could not get next record");
        let result = record_to_string(&record);
        // if counter == 0 {
        //     println!("{}", result);
        // }
        counter = counter + 1;


        write_csv_line_to_file(result, counter, &mut path);
    }
    println!("{}", counter+1);
}