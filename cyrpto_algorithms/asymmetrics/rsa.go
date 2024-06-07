package asymmetric

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
)

// RSAKeyPair represents an RSA key pair.
type RSAKeyPair struct {
	PublicKey  *RSAPublicKey
	PrivateKey *RSAPrivateKey
}

// RSAPublicKey represents an RSA public key.
type RSAPublicKey struct {
	N *big.Int // Modulus
	E *big.Int // Public exponent
}

// RSAPrivateKey represents an RSA private key.
type RSAPrivateKey struct {
	N *big.Int // Modulus
	D *big.Int // Private exponent
}

// GenerateRSAKeyPair generates a new RSA key pair.
func GenerateRSAKeyPair(bits int) (*RSAKeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	publicKey := &RSAPublicKey{
		N: key.N,
		E: big.NewInt(65537),
	}

	privateKey := &RSAPrivateKey{
		N: key.N,
		D: key.D,
	}

	return &RSAKeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

func EncryptRSA(plainText []byte, pub *RSAPublicKey) ([]byte, error) {
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, pubKeyToRSA(pub), plainText)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

// DecryptRSA decrypts ciphertext using RSA decryption with a given private key.
func DecryptRSA(cipherText []byte, keyPair *RSAKeyPair) ([]byte, error) {
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privKeyToRSA(keyPair), cipherText)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

// Helper function to convert RSAPublicKey to *rsa.PublicKey
func pubKeyToRSA(pub *RSAPublicKey) *rsa.PublicKey {
	return &rsa.PublicKey{
		N: pub.N,
		E: int(pub.E.Int64()),
	}
}

// Helper function to convert RSAPrivateKey to *rsa.PrivateKey
func privKeyToRSA(keypair *RSAKeyPair) *rsa.PrivateKey {
	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: keypair.PublicKey.N,
			E: 65537, // Set the public exponent to a fixed value
		},
		D: keypair.PrivateKey.D,
		Primes: []*big.Int{
			new(big.Int).Set(keypair.PublicKey.N), // Use the modulus of the public key
			new(big.Int).Set(keypair.PrivateKey.D),
		},
	}
}

// WriteRSAKeysToFile writes the RSA public and private keys to separate files.
func WriteRSAKeysToFile(keyPair *RSAKeyPair, publicKeyFile, privateKeyFile string) error {
	// Write public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{
		N: keyPair.PublicKey.N,
		E: int(keyPair.PublicKey.E.Int64()),
	})
	if err != nil {
		return err
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	err = ioutil.WriteFile(publicKeyFile, pem.EncodeToMemory(publicKeyBlock), 0644)
	if err != nil {
		return fmt.Errorf("error writing public key to file: %v", err)
	}

	// Write private key to file
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(&rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: keyPair.PublicKey.N,
			E: int(keyPair.PublicKey.E.Int64()),
		},
		D: keyPair.PrivateKey.D,
		Primes: []*big.Int{
			new(big.Int).Set(keyPair.PrivateKey.N),
			new(big.Int).Set(keyPair.PrivateKey.D),
		},
	})
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	err = ioutil.WriteFile(privateKeyFile, pem.EncodeToMemory(privateKeyBlock), 0644)
	if err != nil {
		return fmt.Errorf("error writing private key to file: %v", err)
	}

	return nil
}

// InitRSA generates an RSA key pair, encrypts and decrypts a message,
// and writes the keys to separate files.
func InitRSA() {
	// Generate RSA Key Pair
	bits := 2048 // Change this to desired key size
	rsaKeyPair, err := GenerateRSAKeyPair(bits)
	if err != nil {
		fmt.Println("Error generating RSA key pair:", err)
		return
	}

	// Original message
	originalMessage := []byte("Hello, RSA!")

	// Encrypt the message using RSA
	cipherText, err := EncryptRSA(originalMessage, rsaKeyPair.PublicKey)
	if err != nil {
		fmt.Println("Error encrypting message:", err)
		return
	}

	// Decrypt the ciphertext using RSA
	decryptedMessage, err := DecryptRSA(cipherText, rsaKeyPair)
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return
	}

	// Print original, encrypted, and decrypted messages
	fmt.Println("Original message:", string(originalMessage))
	fmt.Println("Encrypted message:", string(cipherText))
	fmt.Println("Decrypted message:", string(decryptedMessage))

	// Write keys to files
	err = WriteRSAKeysToFile(rsaKeyPair, "RSAPublicKey.pem", "RSAPrivateKey.pem")
	if err != nil {
		fmt.Println("Error writing RSA keys to files:", err)
		return
	}

	fmt.Println("RSA keys written to files: RSAPublicKey.pem, RSAPrivateKey.pem")
}
