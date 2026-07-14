On June 26, 2026, I encoded the Project Gutenberg corpus into a Merkle tree and wrote the root hash on the Bitcoin blockchain at [block 955522](https://blockstream.info/tx/b82b914e29fb08e65e49156231b68c38c3bcb246f6a7d8ec22477478a9f1b832?expand). This comprises a secure timestamp of the Project Gutenberg corpus. In other words, the Merkle tree and the block containing its root hash provide cryptographic-strength proof that each Project Gutenberg text existed in June 2026.

Proving that texts existed in 2026 may be valuable in the future if advances in LLMs make it cheap to produce convincing forgeries of cultural texts. By proving that a text existed in 2026, we may be able to conclude that it is genuine because it predates these large-scale forgery methods.

For more information on why I did this and how it works, see my writeup [here](https://www.davidtench.com/timestamp). 

This repo has two purposes. 

First, you can use it to verify the June 26, 2026 Merkle tree timestamp and then use the Merkle tree to authenticate PG files. Doing so proves that the files in question existed on June 26, 2026.

Second, this repo is a reference implementation: it is the source code I used to build the Merkle tree and compose the blockchain message. You can use it to generate a Merkle tree file from scratch using a copy of the Project Gutenberg Corpus.

I will soon fork this repo to create a version that you can use to create your own secure timestamps of corpuses.

## Requirements
This project requires Rust and OpenSSL.
It has been tested with rustc version 1.88.0 and openssl version 3.0.13.

## Quick Start: Verifying the Merkle tree and then authenticating PG files.
Follow these steps to download and verify my Merkle tree and use it to verify Project Gutenberg files.
1. Clone this repo and `cd` into the directory.
2. Download the merkle tree file [here](https://www.davidtench.com/downloads/pgmerkle.txt). Place it in the canonical_timestamp subdirectory.
3. Run `cargo run --release -- -t`. It will print out the exact message that should appear on the blockchain.
4. Inspect [this Bitcoin transaction in block 955522](https://blockstream.info/tx/b82b914e29fb08e65e49156231b68c38c3bcb246f6a7d8ec22477478a9f1b832?expand). Click on the "Details" link, which will reveal an OP_RETURN output whose SCRIPTPUBKEY hex dump should match the hex dump you got from step 3 exactly. **If it does match, you have verified the timestamp.** This means that you have proven that the Merkle tree and explain.txt files are the ones I timestamped on June 26, 2026.
#### Authenticating a PG file
5. Download any plain text file from Project Gutenberg.
6. `cargo run --release -- -v <path to your PG file>`

## Reproducing Timestamp Generation

### To automatically generate your own version of explain.txt and the blockchain message:
7. Generate an ECDSA private key and a corresponding public key.
8. In config.toml, set private_key_path and public_key_path to point to the keys you just generated.
9. Set the date, time, and block_lockout values in config.toml to whatever you desire.
10. Run `cargo run --release -- -g`
11. Now explain.txt and tag.txt have been written in the generated_timestamp subdirectory.

### If you want to build your own Merkle tree from scratch:
12. Download the June 11th version of the PG corpus [here](https://drive.proton.me/urls/TREXY65MA8#ku23FKKn2Nbm). NOTE: This file is about 10GB in size.
13. Extract the files from the tarball. NOTE: This will uncompress 77113 text files totalling about 16GB, so extract to an appropriate location.
14. In config.toml, set corpus_path to the directory containing the extracted files.
15. Run `cargo run --release -- -b`. This will build the merkle tree from the files and write the resulting tree to generated_timestamp/pgmerkle.txt. Building the Merkle tree may take some time. It will also generate an explain.txt and tag.txt as above.
16. `diff canonical_timestamp/pgmerkle.txt generated_timestamp/pgmerkle.txt` should either show that the files are identical, or that they differ only on the first header line (if you edited the date to something other than June 26).

## Quick Reference
After completing all the above steps, you can: 
- verify a file using `cargo run --release -- -v <path to your file>`
- automatically generate explain.txt and tag.txt with `cargo run --release -- -g`
- build your own Merkle tree from scratch with `cargo run --release -- -b`

## Testing
Run `cargo test --release`. If you have completed steps 12-16, you can run `cargo test --release -- --ignored` to run a larger set of tests that includes rebuilding the Merkle tree from the corpus and confirming that it verifies each files in the corpus correctly. This larger set of tests will take a while to run.