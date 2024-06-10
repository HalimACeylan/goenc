# GoEnc
Encryption Software which supports existing algorithms with GO


# introduction

The goal was to write a tool in Golang that Supports Modern Encryption Algorithms.
Supported Methods: Hashing, Symmetric Encryption, Asymmetric Encryption
Supported Algorithms: MD5, SHA-1, SHA-256, SHA-512, AS-128 , AES, BLOWFISH, ElGamal,ECC, RSA
 

# Installation from source code
go build goenc.go 

./goenc 

# Usage of flags
- `-asymmetric` is the flag for the use of asymmetric encryption
- `-symmetric` is the flag for the use of symmetric encryption
- `-hash` is the flag for use of hashing
- `-algorithm` is for which algorithm will be used such as "sha1" or "aes" depending on the encryption type
- `-operation` is for "encryption", "decryption", "generate", "sign" for only ecc sign a document, "verify" for only ecc for verifying the signature
- `-f` is for the input file it may be an encrypted file or plain text
- `-key` depends on your operation, and algorithm it can be a private, public key, or binary key for symmetric encryption
- `-sig` is you signed a document with "ecc" encryption you can validate the signature of the document with a signature file
# Algorithms

## Hashing
- [x] MD5
- [x] SHA-1
- [x] SHA-256
- [x] SHA-512

## Asymmetric Encryption
- [x] RSA
- [X] ECC
- [x] Elgamal
## Symmetric Encryption
- [X] AES
- [x] Blowfish

# Implementation 

## Asymmetric 

https://github.com/HalimACeylan/goenc/assets/64225727/95efc83b-8ed1-42e6-a1c5-ab70c4eec65f



