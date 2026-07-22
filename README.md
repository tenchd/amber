Amber is a Rust utility that makes it easy to:
- create a cryptographically-secure timestamp of a corpus, and
- verify and use timestamps that others have created

It is based on the [reference implementation](https://github.com/tenchd/secure_timestamp) associated with the [June 2026 secure timestamp](https://www.davidtench.com/timestamp) of the Project Gutenberg corpus.

A **secure timestamp** is a digital artifact that can be used to prove with a high degree of certainty that texts from a corpus existed at a particular date (and therefore were not created after that date). This may be valuable in the future if new, hard-to-detect methods of altering or forging documents are invented, because the existence of such methods would cast doubt on the authenticity of genuine digital texts. Proving that a document existed before the forgery methods were created would help to prove the document's authenticity.

For more about the motivation to produce and use secure timestamps, see this article I wrote here.

A secure timestamp consists of several components:
- A Merkle tree built from all of the files in the corpus
- A text document that explains how to use it and the Merkle tree to verify the timestamp
- A short message, derived from the Merkle tree and text document, written to the Bitcoin blockchain at a particular location
- (Optional but recommended) the corpus files preserved exactly as they were at the time the Merkle tree was created.

Specifically, the blockchain message contains both the root hash of the Merkle tree and the double SHA256 hash of the explanatory text document. Since the blockchain message is tamper-proof and is inherently timestamped, it establishes the existence of each of the files in the corpus at the time the message was written to the blockchain.

Secure timestamps grow more useful the older they are. A primary design goal of secure timestamps is *self-sufficiency*: a secure timestamp should be usable even after institutional knowledge about it has completely disappeared. Someone who encounters a secure timestamp and has no access to this repository, the creators of the timestamp, or any institutional knowledge about secure timestamps in general, should be able to reconstruct and use the Merkle tree. The only external requirements are that the blockchain message persists (so that it can establish the time at which the timestamp was created), and that the unaltered corpus files are available. The only requirements of this hypothetical future user are that they can understand English and can write code. 

Merkle tree files may be large because they contain information about all files in the corpus. It is possible to create a Merkle proof file which only contains the information required to verify the timestamp for a single specific file in the corpus. This repo also supports the creation, verification and use of Merkle proofs.

## Quick Start: Verifying and Using an Existing Secure Timestamp.
This repo includes a secure timestamp of the Project Gutenberg corpus as it existed on June 26, 2026. The Merkle tree file and explanatory document for this timestamp can be found in `testing/reference_timestamp/`. In addition, a single file from the corpus and its corresponding Merkle proof file can be found in `testing/`.

1. Clone this repo and `cd` into the directory.
2. `cp example_config.toml config.toml`
3. Edit the last two lines in config.toml to read:
```
provided_tree_path = "testing/reference_timestamp/pgmerkle.txt"
provided_explain_path = "testing/reference_timestamp/canonical_pg_explain.txt"
```
4. `cargo run --release -- -v`

You should see some output beginning with `Verifying timestamp in testing/reference_timestamp/pgmerkle.txt`. 

After a few seconds, you should see the message 
```
Success! The transaction was found in block 955522 and contains the tag in its OP_RETURN data payload.
You have verified that the provided timestamp was written to the Bitcoin blockchain at date/time 2026-06-26 16:44:23 UTC
```

This means the code has verified via the Bitcoin blockchain that the secure timestamp in `testing/reference_timestamp` existed on June 26, 2026. Since it is a timestamp of the Project Gutenberg corpus, you can use it to verify Project Gutenberg text files. One such file is `testing/pg996.txt`, which is the novel Don Quixote. Verify it as follows:

5. `cargo run --release -- -f testing/pg996.txt`

You should see the following output:
```
Reading merkle tree from file testing/reference_timestamp/pgmerkle.txt.
Merkle tree has root hash: e56bf7ee... and contains 77113 leaves
Merkle tree is valid.
testing/pg996.txt is in the Merkle tree.
```

If you try another verifying another file which is not part of the PG corpus (I made an empty file called `unrelated_file.txt` for this example) you will see output like the following:

```
Reading merkle tree from file testing/reference_timestamp/pgmerkle.txt.
Merkle tree has root hash: e56bf7ee... and contains 77113 leaves
Merkle tree is valid.
unrelated_file.txt is NOT in the Merkle tree.
```

which informs you that the file is not in the Merkle tree, and therefore we have no information about when `unrelated_file.txt` was created.

Incidentally, if you would like to download the entire June 26, 2026 Project Gutenberg corpus, you can get it [here](https://drive.proton.me/urls/TREXY65MA8#ku23FKKn2Nbm). Each file in this corpus can be verified using the above steps.

Now that you see how this procedure works, you can use this method to verify any Amber v1 secure timestamp you encounter - simply change the `provided_tree_path` and `provided_explain_path` config variables to the locations of the merkle tree and explain files from the timestamp.

### Verifying a Merkle Proof File
You can use a Merkle proof file to verify a specific document in the corpus without requiring the whole Merkle tree file. Do so as follows:

6. `cargo run --release -- -p testing/pg996_proof.txt -f testing/pg996.txt`

You should see similar output (both for success and failure) as you did for the steps using the Merkle tree to verify files.

## Building a New Secure Timestamp
You will need a Bitcoin wallet that has some amount of Bitcoin available. I provide instructions for using [Electrum](https://electrum.org/), but you may use any method that allows you to submit Bitcoin transactions that include OP_RETURN scripts in outputs.

Building a secure timestamp has three steps:
1) Automatically generating the Merkle tree and automatically writing the explain.txt file. This also automatically produces the message to be written to the blockchain.
2) Writing the message to the blockchain.
3) After the blockchain transaction is accepted, writing the transaction hash and the exact block it appears in to the Merkle tree file header.

This repository automates steps 1) and 3). You must do step 2) yourself (though this repo provides detailed instructions for how to do it). Further, for reasons I will make clear shortly, step 2) should be performed soon after step 1). However, note that writing a message to the Bitcoin blockchain is an **irreversible** action! You must make sure you write *exactly* the message you intend to write, because if it is wrong you cannot edit it later.

So on the one hand you want to do 2) shortly after 1), but you also want to check the output of 1) carefully before doing 2).

My recommendation is to follow these directions once without writing anything to the blockchain, to familiarize yourself with the process and identify any issues ahead of time. Also carefully examine the merkle tree and explain files produced by following the process: read the explain file completely and carefully read the headers of the merkle tree file. Make sure everything looks correct! If something looks wrong, STOP and figure out the issue before writing anything to the blockchain.

With those warnings out of the way, here is how to produce the timestamp:

### First Step: Generating the Merkle Tree and Explain.txt
1. Edit `editable_templates/corpus_description.txt` so that it contains a short description of the corpus you are timestamping. I recommend you address what files are included in the corpus and where they come from.
2. Edit `editable_templates/corpus_motivation.txt` so that it contains a short description of your motivation for timestamping the corpus. Why do you feel it might be valuable to preserve?
3. Edit `editable_templates/user_description.txt` so that it contains a short description of you, the person or organization creating the timestamp.
4. Determine the current height of the Bitcoin blockchain in blocks. (You can do this by visiting https://findtheblock.com/tools/latest-blocks and noting the current chain height.)
5. Set the following variables in config.toml:
`corpus_path`: set to the top-level directory containing the corpus you wish to timestamp. Note that the code will search the directory recursively and include every non-directory file in the Merkle tree.
`corpus_name`: a short name for the corpus.
`date`: the current date.
`time`: the current time.
`locktime`: set this equal to the block height you want your message-writing transaction to appear in. I recommend setting it equal to one plus the current height of the chain (the value you determined in step 4).
`identifier`: any 8-character ASCII string you like. Ideally it will be related to the name of your corpus. This will appear at the beginning of the blockchain message and indicate that the message is part of a secure timestamp.
6. Run `cargo run --release -- -b`. This will write three files to the `generated_timestamp` subdirectory:
- `merkle.txt_unfinished.txt`: an "unfinished" version of the merkle tree file that does not yet have the blockchain location information added.
- `explain.txt`: the canonical explain.txt file for your timestamp. Do not alter it!
- `tag.txt`: The hex dump of the message you will write to the blockchain in the next step.

Take *at least sixty seconds* to examine explain.txt, and to make sure that the Merkle tree has the number of leaves you expect (equal to the number of files in the corpus.

### Second Step: Writing to the Blockchain
Submit a transaction to the Bitcoin blockchain with a 0-sat output whose script is a single OP_RETURN command which writes the exact 76-byte hash dump contained in `generated_timestamp/tag.txt`. If you are not familiar with how to do this, I recommend you follow [this guide](https://planb.academy/en/tutorials/wallet/desktop/electrum-opreturn-46cd3701-cb52-4dda-8251-9fd10e8f8542). I further recommend that you set a relatively high transaction fee to increase the odds that your transaction is mined quickly, ideally within one or two blocks (the guide indicates how to do this).

Wait until the transaction is mined into a block, and then for five subsequent blocks to be mined. At this point the transaction has been confirmed by six blocks and can be considered secure and final. 

Note the height of the block that the transaction was mined in, as well as the transaction hash.

### Third Step: Finalizing the Timestamp
These last steps write the location of your message on the blockchain into merkle.txt, to allow for automatic verification of your timestamp (using the quickstart directions above).
1. Set the following variables in `config.toml`:
`block_height`: the exact height of the block containing your accepted Bitcoin transaction.
`tx_hash`: the hash of your accepted Bitcoin transaction
2. `cargo run --release -- -g`

To make sure everything worked correctly, you can set the following variables in `config.toml`:
```
provided_tree_path = "generated_timestamp/merkle.txt"
provided_explain_path = "generated_timestamp/explain.txt"
```

and run `cargo run --release -- -v`. If your timestamp passes verification, you know you have succeeded. Congratulations!


### Creating a Merkle Proof from an Existing Verified Timestamp
You can create your own Merkle proof from an existing timestamp, given one of the files from the corresponding corpus, as follows:

`cargo run --release -- -m <filepath>`

where `<filepath>` is the path to the corpus file you wish to produce a proof for.

Note that the code will attempt to verify the proof on the blockchain and will not write the proof to fail if verification fails.