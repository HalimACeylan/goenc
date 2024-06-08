package asymmetric

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// GenerateRSAKeyPair generates a new RSA key pair.
func GenerateRSAKeyPair() (*rsa.PrivateKey, error) {
	bits := 2048
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// WriteRSAKeysToFile writes the RSA public and private keys to separate files.
func WriteRSAKeysToFile(privateKey *rsa.PrivateKey, publicKeyFile, privateKeyFile string) error {
	// Write public key to file.
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	err = ioutil.WriteFile(publicKeyFile, pem.EncodeToMemory(publicKeyBlock), 0644)
	if err != nil {
		fmt.Printf("error writing public key to file: %v", err)
	}

	// Write private key to file.
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	err = ioutil.WriteFile(privateKeyFile, pem.EncodeToMemory(privateKeyBlock), 0644)
	if err != nil {
		fmt.Printf("error writing private key to file: %v", err)
	}

	return nil
}

// ReadPrivateKeyFromFile reads an RSA private key from a PEM file.
func ReadPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading private key file: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded private key: %v", err)
	}

	return privateKey, nil
}

// ReadPublicKeyFromFile reads an RSA public key from a PEM file.
func ReadPublicKeyFromFile(filename string) (*rsa.PublicKey, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded public key: %v", err)
	}

	rsaPubKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not RSA public key")
	}

	return rsaPubKey, nil
}

// EncryptFileRSA encrypts the contents of a file using RSA.
func EncryptFileRSA(inputFile, keyFile string) error {
	// Read plaintext from file
	plainText, err := ioutil.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("error reading input file: %v", err)
	}

	// Read RSA public key from file
	publicKey, err := ReadPublicKeyFromFile(keyFile)
	if err != nil {
		fmt.Printf("error reading public key file: %v", err)
	}

	// Encrypt plaintext using RSA
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil {
		fmt.Printf("error encrypting data: %v", err)
	}

	// Write ciphertext to file
	err = ioutil.WriteFile("RSA_encrypted_message.txt", cipherText, 0644)
	if err != nil {
		fmt.Printf("error writing encrypted data to file: %v", err)
	}

	return nil
}

// DecryptFileRSA decrypts the contents of a file using RSA.
func DecryptFileRSA(inputFile, keyFile string) error {
	// Read ciphertext from file
	cipherText, err := ioutil.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("error reading input file: %v", err)
	}

	// Read RSA private key from file
	privateKey, err := ReadPrivateKeyFromFile(keyFile)
	if err != nil {
		fmt.Printf("error reading private key file: %v", err)
	}

	// Decrypt ciphertext using RSA
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	if err != nil {
		fmt.Printf("error decrypting data: %v", err)
	}

	fmt.Printf("Decrypted message: %s\n", plainText)

	return nil
}
func GenerateRSAKeyPairFiles() error {
	// Generate RSA key pair
	keyPair, err := GenerateRSAKeyPair()
	if err != nil {
		fmt.Printf("error generating RSA key pair: %v", err)
		return err
	}
	WriteRSAKeysToFile(keyPair, "RSA_public_key.pem", "RSA_private_key.pem")
	return nil
}
