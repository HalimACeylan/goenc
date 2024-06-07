package asymmetric

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// GenerateECCKeyPair generates a new ECC key pair.
func GenerateECCKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

// SignMessageWithECC signs a message using ECC.
func SignMessageWithECC(privateKey *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	return ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
}

// VerifySignatureWithECC verifies the signature of a message using ECC.
func VerifySignatureWithECC(publicKey *ecdsa.PublicKey, message, signature []byte) bool {
	hash := sha256.Sum256(message)
	valid := ecdsa.VerifyASN1(publicKey, hash[:], signature)
	return valid
}

// WriteECCKeysToFile writes the ECC private and public keys to separate files.
func WriteECCKeysToFile(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey, privateKeyFile, publicKeyFile string) error {
	// Write private key to file
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}
	privateKeyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	if err := ioutil.WriteFile(privateKeyFile, pem.EncodeToMemory(privateKeyBlock), 0644); err != nil {
		return fmt.Errorf("error writing private key to file: %v", err)
	}

	// Write public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	if err := ioutil.WriteFile(publicKeyFile, pem.EncodeToMemory(publicKeyBlock), 0644); err != nil {
		return fmt.Errorf("error writing public key to file: %v", err)
	}

	return nil
}

func InitECC(messageFile, publicKeyFile, privateKeyFile, signatureFile string) {
	// Generate ECC key pair
	privateKey, err := GenerateECCKeyPair()
	if err != nil {
		fmt.Println("Error generating ECC key pair:", err)
		return
	}
	publicKey := &privateKey.PublicKey

	// Write keys to files
	err = WriteECCKeysToFile(privateKey, publicKey, publicKeyFile, privateKeyFile)
	if err != nil {
		fmt.Println("Error writing ECC keys to files:", err)
		return
	}

	// Read message from file
	message, err := ioutil.ReadFile(messageFile)
	if err != nil {
		fmt.Println("Error reading message from file:", err)
		return
	}

	// Sign message
	signature, err := SignMessageWithECC(privateKey, message)
	if err != nil {
		fmt.Println("Error signing message:", err)
		return
	}

	// Write signature to file
	err = ioutil.WriteFile(signatureFile, signature, 0644)
	if err != nil {
		fmt.Println("Error writing signature to file:", err)
		return
	}
	fmt.Println("Signature written to file:", signatureFile)

	// Verify signature
	valid := VerifySignatureWithECC(publicKey, message, signature)
	if valid {
		fmt.Println("Signature is valid.")
	} else {
		fmt.Println("Signature is invalid.")
	}
}
