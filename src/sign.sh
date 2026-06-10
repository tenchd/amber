#!/bin/bash
# fill in the four variables below with the correct values
private_key_path="private_key.pem"
public_key_path="public_key.pem"
merkle_root_hash="8f2cb7ce0b83bcab38cb7957a4ef0d68c8872ab452e2d7abafcab1c49f90e205"
date="June 10, 2026"
output_document="../test_example.txt"

message="${merkle_root_hash} ${date}"

echo $message | openssl dgst -sha256 -binary > message.bin
openssl pkeyutl -sign -in message.bin -inkey $private_key_path -out signature.bin
openssl pkeyutl -verify -in message.bin -sigfile signature.bin -inkey $public_key_path -pubin
openssl enc -base64 -in signature.bin -out signature.b64
rm signature.bin
rm message.bin


cat $public_key_path >> $output_document
echo "Signature of message \"${message}\":" >> $output_document
cat signature.b64 >> $output_document
rm signature.b64