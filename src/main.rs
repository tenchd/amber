#[allow(unused_parens)]

use config::Config;
use clap::Parser;
use amber::{build_timestamp, finalize_timestamp, verify_proof, verify_tree, verify_file, make_proof, parse_hash_from_string};

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

fn main() {
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

        build_timestamp(&corpus_path, &hashes_path, args.hash_source, &generated_tree_filename, &generated_explain_filename, &generated_tag_filename, &corpus_name, locktime, &identifier);

    }
    else if args.generate_timestamp {
        if args.file_to_verify != "".to_string() {
            println!("Ignoring verification request. Building timestamp.");
        }
        let tx_hash_string = settings.get_string("tx_hash").unwrap();
        let tx_hash = parse_hash_from_string(&tx_hash_string);
        // need to read in unfinished merkle file, build a timestamped merkle file from it, verify the timestamp on the chain, then write to the timestamped tree to file.
        
        finalize_timestamp(generated_tree_filename, generated_explain_filename, &corpus_name, &identifier, tx_hash);

    }
    else if args.verify_timestamp {
        _ = verify_tree(&provided_tree_filename, &provided_explain_filename);
    }
    else if args.file_to_verify != "".to_string() {
        let filepath = args.file_to_verify;
        if args.proof_verify != "".to_string() {
            let proof_file = args.proof_verify;
            _ = verify_proof(&filepath, &proof_file);
        }
        else {
            _ = verify_file(&provided_tree_filename, &filepath);
        }
    }
    else if args.make_proof != "".to_string() {
        let input_path: String = args.make_proof;
        make_proof(&input_path, &provided_tree_filename, &corpus_name);
    }
    else {
        panic!("Need to provide a command line argument");
    }

}
