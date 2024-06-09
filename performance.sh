#!/bin/bash

# Input file to be encrypted
input_file="message.txt"

# Generate a random key for encryption
openssl rand -base64 32 > key.bin

# Measure time taken by OpenSSL encryption
echo "Performing encryption using OpenSSL..."
time openssl enc -aes-256-cbc -salt -in "$input_file" -out "openssl_encrypted.enc" -pass file:key.bin -pbkdf2

# Measure time taken by Go encryption
echo "Performing encryption using Go..."
time ./goenc -symmetric -algorithm "aes" -operation "encrypt" -key "key.bin" -f "$input_file"

# Cleanup
rm key.bin openssl_encrypted.enc