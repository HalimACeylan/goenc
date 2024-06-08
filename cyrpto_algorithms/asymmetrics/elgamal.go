package asymmetric

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
)

// ElGamalKeyPair represents an ElGamal key pair.
type ElGamalKeyPair struct {
	PublicKey  *ElGamalPublicKey
	PrivateKey *ElGamalPrivateKey
}
type ElGamalEncryptedMessage struct {
	C1 string
	C2 string
}

// ElGamalPublicKey represents an ElGamal public key.
type ElGamalPublicKey struct {
	P *big.Int // Prime modulus
	G *big.Int // Generator
	Y *big.Int // Public key
}

// ElGamalPrivateKey represents an ElGamal private key.
type ElGamalPrivateKey struct {
	X *big.Int // Private key
	P *big.Int // Prime modulus
}

// GenerateElGamalKeyPair generates a new ElGamal key pair.
func GenerateElGamalKeyPair(bits int) (*ElGamalKeyPair, error) {
	// Generate a safe prime (p)
	p, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	// Compute generator (g)
	pMinusThree := new(big.Int).Sub(p, big.NewInt(3))
	g, err := rand.Int(rand.Reader, pMinusThree)
	if err != nil {
		return nil, err
	}
	g.Add(g, big.NewInt(2)) // g = g + 2

	// Generate a private key (x)
	x, err := rand.Int(rand.Reader, p)
	if err != nil {
		return nil, err
	}

	// Compute public key (y = g^x mod p)
	y := new(big.Int).Exp(g, x, p)

	publicKey := &ElGamalPublicKey{
		P: p,
		G: g,
		Y: y,
	}

	privateKey := &ElGamalPrivateKey{
		X: x,
		P: p,
	}

	return &ElGamalKeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// EncryptElGamal encrypts plaintext using ElGamal encryption with a given public key.
func EncryptElGamal(plainText *big.Int, pub *ElGamalPublicKey) (*big.Int, *big.Int, error) {
	// Choose a random integer k such that 1 <= k <= p-2
	k, err := rand.Int(rand.Reader, new(big.Int).Sub(pub.P, new(big.Int).SetInt64(2)))
	if err != nil {
		return nil, nil, err
	}

	// Compute c1 = g^k mod p
	c1 := new(big.Int).Exp(pub.G, k, pub.P)

	// Compute c2 = (plaintext * y^k) mod p
	c2 := new(big.Int).Mod(new(big.Int).Mul(plainText, new(big.Int).Exp(pub.Y, k, pub.P)), pub.P)

	return c1, c2, nil
}

// DecryptElGamal decrypts ciphertext using ElGamal decryption with a given private key.
func DecryptElGamal(c1, c2 *big.Int, priv *ElGamalPrivateKey) (*big.Int, error) {
	// Compute s = c1^x mod p
	s := new(big.Int).Exp(c1, priv.X, priv.P)

	// Compute plaintext = (c2 * s^-1) mod p
	sInverse := new(big.Int).ModInverse(s, priv.P)
	if sInverse == nil {
		return nil, fmt.Errorf("failed to compute modular inverse")
	}
	plainText := new(big.Int).Mod(new(big.Int).Mul(c2, sInverse), priv.P)

	return plainText, nil
}

// ReadElGamalEncryptedMessageFromFile reads the ElGamal encrypted message from a JSON file.
func ReadElGamalEncryptedMessageFromFile(messageFile string) (*big.Int, *big.Int, error) {
	// Read the encrypted message from file
	messageBytes, err := ioutil.ReadFile(messageFile)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading message file: %v", err)
	}

	// Decode JSON to ElGamalEncryptedMessage struct
	var encryptedMessage ElGamalEncryptedMessage
	err = json.Unmarshal(messageBytes, &encryptedMessage)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding encrypted message from JSON: %v", err)
	}

	// Convert c1 and c2 to big.Int
	c1, ok := new(big.Int).SetString(encryptedMessage.C1, 10)
	if !ok {
		return nil, nil, fmt.Errorf("invalid value for c1")
	}
	c2, ok := new(big.Int).SetString(encryptedMessage.C2, 10)
	if !ok {
		return nil, nil, fmt.Errorf("invalid value for c2")
	}

	return c1, c2, nil
}

// ReadStringFromFile reads a string from a file.
func ReadStringFromFile(filename string) (string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("error reading input file: %v", err)
	}
	return string(data), nil
}

// WriteElGamalKeysToFile writes the ElGamal public and private keys to separate JSON files.
func WriteElGamalKeysToFile(keyPair *ElGamalKeyPair, publicKeyFile, privateKeyFile string) error {
	// Encode ElGamal public key to JSON format
	pubKeyBytes, err := json.Marshal(keyPair.PublicKey)
	if err != nil {
		return fmt.Errorf("error encoding public key to JSON: %v", err)
	}
	err = ioutil.WriteFile(publicKeyFile, pubKeyBytes, 0644)
	if err != nil {
		return fmt.Errorf("error writing public key to file: %v", err)
	}

	// Encode ElGamal private key to JSON format
	privKeyBytes, err := json.Marshal(keyPair.PrivateKey)
	if err != nil {
		return fmt.Errorf("error encoding private key to JSON: %v", err)
	}
	err = ioutil.WriteFile(privateKeyFile, privKeyBytes, 0644)
	if err != nil {
		return fmt.Errorf("error writing private key to file: %v", err)
	}

	return nil
}

func WriteElGamalEncryptedMessageToFile(c1, c2 *big.Int, messageFile string) error {
	// Encode c1 and c2 to JSON format
	encryptedMessage := ElGamalEncryptedMessage{
		C1: c1.String(),
		C2: c2.String(),
	}
	messageBytes, err := json.Marshal(encryptedMessage)
	if err != nil {
		return fmt.Errorf("error encoding encrypted message to JSON: %v", err)
	}

	// Write JSON to file
	err = ioutil.WriteFile(messageFile, messageBytes, 0644)
	if err != nil {
		return fmt.Errorf("error writing encrypted message to file: %v", err)
	}

	return nil
}

// ReadElGamalPrivateKeyFromFile reads the ElGamal private key from a JSON file.
func ReadElGamalPrivateKeyFromFile(privateKeyFile string) (*ElGamalPrivateKey, error) {
	// Read private key from file
	privKeyBytes, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading private key from file: %v", err)
	}

	// Decode JSON to ElGamalPrivateKey struct
	var privateKey ElGamalPrivateKey
	err = json.Unmarshal(privKeyBytes, &privateKey)
	if err != nil {
		return nil, fmt.Errorf("error decoding private key from JSON: %v", err)
	}

	return &privateKey, nil
}

func ReadElGamalPublicKeyFromFile(publicKeyFile string) (*ElGamalPublicKey, error) {
	// Read public key from file
	pubKeyBytes, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading public key from file: %v", err)
	}

	// Decode JSON to ElGamalPublicKey struct
	var publicKey ElGamalPublicKey
	err = json.Unmarshal(pubKeyBytes, &publicKey)
	if err != nil {
		return nil, fmt.Errorf("error decoding public key from JSON: %v", err)
	}

	return &publicKey, nil
}

func ElgamalGenerateKeys() {
	elGamalKeyPair, err := GenerateElGamalKeyPair(256)
	if err != nil {
		fmt.Println("Error generating ElGamal key pair:", err)
		return
	}
	// Write keys to files
	err = WriteElGamalKeysToFile(elGamalKeyPair, "ElGamal_public_key.json", "ElGamal_private_key.json")
	if err != nil {
		fmt.Println("Error writing ElGamal keys to files:", err)
		return
	}
}
func ElgamalDecryptMessageWithPrivateKey(inputeFile, privateKeyFile string) error {
	// Read private key from file
	privateKey, err := ReadElGamalPrivateKeyFromFile(privateKeyFile)
	if err != nil {
		return fmt.Errorf("error reading private key from file: %v", err)
	}
	c1, c2, err := ReadElGamalEncryptedMessageFromFile(inputeFile)
	if err != nil {
		return fmt.Errorf("error reading encrypted message from file: %v", err)
	}

	// Decrypt the ciphertext using ElGamal
	decryptedMessage, err := DecryptElGamal(c1, c2, privateKey)
	if err != nil {
		return fmt.Errorf("error decrypting with ElGamal: %v", err)
	}

	// Print decrypted message
	fmt.Println("Decrypted message:", string(decryptedMessage.Bytes()))

	return nil
}
func ElgamalEncryptMessageFromPublicKey(inputeFile, publicKeyFile string) {
	// Read public key from file
	publicKey, err := ReadElGamalPublicKeyFromFile(publicKeyFile)
	if err != nil {
		fmt.Println("Error reading public key from file:", err)
		return
	}
	message, err := ReadStringFromFile(inputeFile)
	if err != nil {
		fmt.Errorf("error reading message from file: %v", err)
		return
	}
	messageInt := new(big.Int).SetBytes([]byte(message))

	// Encrypt the message using ElGamal
	c1, c2, err := EncryptElGamal(messageInt, publicKey)
	if err != nil {
		fmt.Println("Error encrypting with ElGamal:", err)
		return
	}

	// Write encrypted message to file
	err = WriteElGamalEncryptedMessageToFile(c1, c2, "ELGamal_encrypted_message.json")
	if err != nil {
		fmt.Println("Error writing encrypted message to file:", err)
		return
	}
}
