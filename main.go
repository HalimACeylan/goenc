package main

import (
	asymmetric "github.com/HalimACeylan/goenc/cyrpto_algorithms/asymmetrics"
)

func main() {
	// Initialize ElGamal encryption
	//asymmetric.InitElGamal()
	// Generate ECC key pair, sign message, and verify signature
	asymmetric.InitECC("message.txt", "ECC_public_key.pem", "ECC_private_key.pem", "ECC_signature.dat")
}
