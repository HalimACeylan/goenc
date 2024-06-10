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
	fmt.Printf("here is the private key: %v\n", string(privateKeyBytes))

	// Write public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	fmt.Printf("here is the public key: %v\n", string(publicKeyBytes))
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	if err := ioutil.WriteFile(publicKeyFile, pem.EncodeToMemory(publicKeyBlock), 0644); err != nil {
		return fmt.Errorf("error writing public key to file: %v", err)
	}

	return nil
}

// ReadECCPrivateKeyFromFile reads the ECC private key from a PEM file.
func ReadECCPrivateKeyFromFile(privateKeyFile string) (*ecdsa.PrivateKey, error) {
	privateKeyBytes, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading private key file: %v", err)
	}

	block, _ := pem.Decode(privateKeyBytes)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %v", err)
	}

	return privateKey, nil
}

// ReadECCPublicKeyFromFile reads the ECC public key from a PEM file.
func ReadECCPublicKeyFromFile(publicKeyFile string) (*ecdsa.PublicKey, error) {
	publicKeyBytes, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %v", err)
	}

	block, _ := pem.Decode(publicKeyBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %v", err)
	}

	publicKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	return publicKey, nil
}

func ECCgenerateKeys() {
	privateKey, err := GenerateECCKeyPair()
	if err != nil {
		fmt.Println("Error generating ECC key pair:", err)
		return
	}
	publicKey := &privateKey.PublicKey

	// Write keys to files
	err = WriteECCKeysToFile(privateKey, publicKey, "ECC_private_key.pem", "ECC_public_key.pem")
	if err != nil {
		fmt.Println("Error writing ECC keys to files:", err)
		return
	}
}
func ECCsignWithPrivateKey(messageFile string, privateKeyFile string) {
	message, err := ioutil.ReadFile(messageFile)
	if err != nil {
		fmt.Println("Error reading message from file:", err)
		return
	}
	privateKey, err := ReadECCPrivateKeyFromFile(privateKeyFile)
	if err != nil {
		fmt.Println("Error reading private key from file:", err)
		return
	}

	// Sign message
	signature, err := SignMessageWithECC(privateKey, message)
	if err != nil {
		fmt.Println("Error signing message:", err)
		return
	}
	// Write signature to file
	err = ioutil.WriteFile("ECC_signed_message.dat", signature, 0644)
	if err != nil {
		fmt.Println("Error writing signature to file:", err)
		return
	}
	fmt.Println("Signature written to file:", "ECC_signed_message.dat")
}
func ECCverifyWithPublicKey(messageFile string, publicKeyFile string, signatureFile string) {
	message, err := ioutil.ReadFile(messageFile)
	if err != nil {
		fmt.Println("Error reading message from file:", err)
		return
	}
	publicKey, err := ReadECCPublicKeyFromFile(publicKeyFile)
	if err != nil {
		fmt.Println("Error reading public key from file:", err)
		return
	}
	signature, err := ioutil.ReadFile(signatureFile)
	if err != nil {
		fmt.Println("Error reading signature from file:", err)
		return
	}
	// Verify signature
	valid := VerifySignatureWithECC(publicKey, message, signature)
	if valid {
		fmt.Println("Signature is VALID.")
	} else {
		fmt.Println("Signature is INVALID.")
	}
}
