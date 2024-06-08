package main

import (
	"flag"
	"fmt"

	asymmetric "github.com/HalimACeylan/goenc/cyrpto_algorithms/asymmetrics"
	symmetric "github.com/HalimACeylan/goenc/cyrpto_algorithms/symmetrics"
)

func main() {
	// Define flags
	asymmetric := flag.Bool("asymmetric", false, "Choose asymmetric algorithm")
	symmetric := flag.Bool("symmetric", false, "Choose symmetric algorithm")
	hash := flag.Bool("hash", false, "Choose hashing algorithm")
	algo := flag.String("algorithm", "", "Choose algorithm: ecc, rsa, elgamal for asymmetric, aes, blowfish for symmetric, md5, sha1, sha256, sha512, hex for hashing")
	operation := flag.String("operation", "", "Choose operation: encrypt, decrypt, generate")
	key := flag.String("key", "", "Key file path")
	file := flag.String("f", "", "File path")
	signature := flag.String("sig", "", "Signature file path")
	message := flag.String("m", "", "Input message")
	flag.Parse()

	// Check which algorithm is chosen
	if *asymmetric {
		handleAsymmetric(*algo, *operation, *key, *file, *message, *signature)
	} else if *symmetric {
		handleSymmetric(*algo, *operation, *key, *file, *message, *signature)
	} else if *hash {
		handleHash(*algo, *operation, *file, *message, *signature)
	} else {
		fmt.Println("Please choose an algorithm category: asymmetric, symmetric, or hash")
	}
}

func handleAsymmetric(algo, operation, key, file, message, signature string) {
	switch algo {
	case "ecc", "rsa", "elgamal":
		performOperation("asymmetric", algo, operation, key, file, message, signature)
	default:
		fmt.Println("Invalid asymmetric algorithm. Please choose ecc, rsa, or elgamal")
	}
}

func handleSymmetric(algo, operation, key, file, message, signature string) {
	switch algo {
	case "aes", "blowfish":
		performOperation("symmetric", algo, operation, key, file, message, signature)
	default:
		fmt.Println("Invalid symmetric algorithm. Please choose aes or blowfish")
	}
}

func handleHash(algo, operation, file, message, signature string) {
	switch algo {
	case "md5", "sha1", "sha256", "sha512", "hex":
		performOperation("hash", algo, operation, "", file, message, signature)
	default:
		fmt.Println("Invalid hashing algorithm. Please choose md5, sha1, sha256, sha512, or hex")
	}
}

func performOperation(algorithmType, algo, operation, key, file, message, signature string) {
	if operation == "" {
		fmt.Println("Please specify an operation: encrypt, decrypt, or generate")
		return
	}

	if operation != "generate" && key == "" {
		fmt.Println("Please provide key file for encryption or decryption")
		return
	}

	switch operation {
	case "encrypt":
		if file != "" || message != "" {
			fmt.Println("Performing encryption using", algo, "algorithm")
			fmt.Println("Algorithm type:", algorithmType)
			fmt.Println("Key file:", key)
			if file != "" {
				fmt.Println("File to encrypt:", file)
			} else {
				fmt.Println("Message to encrypt:", message)
			}
			if algo == "ecc" {
				asymmetric.ECCsignWithPrivateKey(file, key)
			} else if algo == "elgamal" {
				asymmetric.ElgamalEncryptMessageFromPublicKey(file, key)
			} else if algo == "rsa" {
				asymmetric.EncryptFileRSA(file, key)
			} else if algo == "aes" {
				symmetric.AESEncryptFile(file, key)
			} else {
				fmt.Println("Invalid algorithm. Please choose ecc, rsa, or elgamal")
			}
		} else {
			fmt.Println("Please provide input file or message for encryption")
		}
	case "decrypt":
		if file != "" || message != "" {
			fmt.Println("Performing decryption using", algo, "algorithm")
			fmt.Println("Algorithm type:", algorithmType)
			fmt.Println("Key file:", key)
			if file != "" {
				fmt.Println("File to decrypt:", file)
			} else {
				fmt.Println("Message to decrypt:", message)
			}
			if (algo == "ecc") && (signature != "") {
				asymmetric.ECCverifyWithPublicKey(file, key, signature)
			} else if algo == "elgamal" {
				asymmetric.ElgamalDecryptMessageWithPrivateKey(file, key)
			} else if algo == "rsa" {
				asymmetric.DecryptFileRSA(file, key)
			} else if algo == "aes" {
				symmetric.AESDecryptFile(file, key)
			} else {
				fmt.Println("Invalid algorithm. Please choose ecc, rsa, or elgamal")
			}
		} else {
			fmt.Println("Please provide input file or message for decryption")
		}
	case "generate":
		fmt.Println("Generating keys for", algo, "algorithm")
		if algo == "ecc" {
			asymmetric.ECCgenerateKeys()
		} else if algo == "elgamal" {
			asymmetric.ElgamalGenerateKeys()
		} else if algo == "rsa" {
			asymmetric.GenerateRSAKeyPairFiles()
		} else if algo == "aes" {
			symmetric.GenerateAESKeyFiles()
		} else {
			fmt.Println("Invalid algorithm. Please choose ecc, rsa, or elgamal")
		}
	default:
		fmt.Println("Invalid operation. Please choose encrypt, decrypt, or generate")
	}
}
