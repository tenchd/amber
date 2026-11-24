#[allow(unused_parens)]

use std::path::PathBuf;
use std::process::ExitCode;
use config::Config;
use clap::Parser;
use amber_core::{Warning, build_timestamp, finalize_timestamp, make_proof, parse_hash_from_string, verify_file, verify_proof, verify_tree};

fn display_warnings(warnings: Vec<Warning>) {
    if warnings.len() > 0 {
        println!("Succeeded, but generated the following warnings:");
        for warning in warnings {
            println!("{warning}");
        }
    }
}

// command line parsing
#[derive(Parser, Debug)]
#[command(version, about, long_about = Option::None)]
struct Args {
    #[arg(short, long, default_value_t = false)]
    build_tree_and_doc: bool,

    #[arg(short, long, default_value_t = false)]
    hash_source: bool,

    #[arg(short, long, default_value_t = false)]
    generate_timestamp: bool,

    #[arg(short, long, default_value_t = false)]
    verify_timestamp: bool,

    #[arg(short, long, default_value_t = String::from(""))]
    file_to_verify: String,

    #[arg(short, long, default_value_t = String::from(""))]
    proof_verify: String,

    #[arg(short, long, default_value_t = String::from(""))]
    make_proof: String,
}

fn main() -> ExitCode {
    let settings = Config::builder()
                    .add_source(config::File::with_name("config"))
                    .build()
                    .unwrap();
    let corpus_path = settings.get_string("corpus_path").unwrap();
    let hashes_path = settings.get_string("hashes_path").unwrap();
    let generated_tree_filename = "generated_timestamp/merkle.txt";
    let generated_explain_filename = "generated_timestamp/explain.txt";
    let generated_tag_filename = "generated_timestamp/tag.txt";
    let provided_tree_filename = settings.get_string("provided_tree_path").unwrap();
    let provided_explain_filename = settings.get_string("provided_explain_path").unwrap();
    let locktime: usize = settings.get_string("locktime").unwrap().parse().expect("couldn't parse block lockout");
    let identifier = settings.get_string("identifier").unwrap();
    let corpus_name = settings.get_string("corpus_name").unwrap();

    let args = Args::parse();

    if args.build_tree_and_doc {
        if args.file_to_verify != "".to_string() {
            println!("Ignoring verification request. Building tree+docs.")
        }

        let result = build_timestamp(&PathBuf::from(corpus_path), &PathBuf::from(hashes_path), args.hash_source, &PathBuf::from(generated_tree_filename), &PathBuf::from(generated_explain_filename), &PathBuf::from(generated_tag_filename), &corpus_name, locktime, &identifier, None, None, None);

        match result {
            Ok((_, warnings)) => {
                display_warnings(warnings);
                return ExitCode::SUCCESS;
            },
            Err(reason) => {
                println!("The timestamp build process failed for the following reason: {}", reason);
                return ExitCode::FAILURE; 
            },
        }

    }
    else if args.generate_timestamp {
        if args.file_to_verify != "".to_string() {
            println!("Ignoring verification request. Building timestamp.");
        }
        let tx_hash_string = settings.get_string("tx_hash").unwrap();
        let tx_hash = match parse_hash_from_string(&tx_hash_string) {
            Ok(hash) => hash,
            Err(reason) => {
                println!("Failed to finalize timestamp for the following reason: {}", reason);
                return ExitCode::FAILURE; 
            },
        };
        // need to read in unfinished merkle file, build a timestamped merkle file from it, verify the timestamp on the chain, then write to the timestamped tree to file.
        
        let (_tree, warnings) = match finalize_timestamp(&PathBuf::from(generated_tree_filename), &PathBuf::from(generated_explain_filename), &corpus_name, &identifier, tx_hash) {
            Ok((val1, val2)) => (val1, val2),
            Err(reason) => {
                println!("Failed to finalize timestamp for the following reason: {}", reason);
                return ExitCode::FAILURE; 
            },
        };
        display_warnings(warnings);
        ExitCode::SUCCESS

    }
    else if args.verify_timestamp {
        let (_tree, warnings) = match verify_tree(&PathBuf::from(provided_tree_filename), &PathBuf::from(provided_explain_filename)) {
            Ok((val1, val2)) => (val1, val2),
            Err(reason) => {
                println!("Timestamp verification failed for the following reason: {reason}");
                return ExitCode::FAILURE;
            },
        };
        display_warnings(warnings);
        ExitCode::SUCCESS
    }
    else if args.file_to_verify != "".to_string() {
        let filepath = args.file_to_verify;
        if args.proof_verify != "".to_string() {
            let proof_file = args.proof_verify;
            let _proof_details = match verify_proof(&PathBuf::from(filepath), &PathBuf::from(proof_file)) {
                Ok(value) => value,
                Err(reason) => {
                    println!("Proof verification failed for the following reason: {reason}");
                    return ExitCode::FAILURE;
                },
            };
            ExitCode::SUCCESS
        }
        else {
            let (_verified, warnings) = match verify_file(&PathBuf::from(provided_tree_filename), &PathBuf::from(filepath)) {
                Ok((val1, val2)) => (val1, val2),
                Err(reason) => {
                    println!("File verification failed for the following reason: {reason}");
                    return ExitCode::FAILURE;
                },
            };
            display_warnings(warnings);
            ExitCode::SUCCESS
        }
    }
    else if args.make_proof != "".to_string() {
        let input_path: String = args.make_proof;
        let warnings = match make_proof(&PathBuf::from(input_path), &PathBuf::from(provided_tree_filename), &PathBuf::from(provided_explain_filename), &corpus_name) {
            Ok(value) => value,
            Err(reason) => {
                println!("Proof construction failed for the following reason: {reason}");
                return ExitCode::FAILURE;
            },
        };
        display_warnings(warnings);
        ExitCode::SUCCESS
    }
    else {
        panic!("Need to provide a command line argument");
    }

}
