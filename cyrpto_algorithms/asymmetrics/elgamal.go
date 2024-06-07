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

// ReadStringFromFile reads a string from a file.
func ReadStringFromFile(filename string) (string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("error reading input file: %v", err)
	}
	fmt.Printf("Read from file: %s\n", data)
	return string(data), nil
}

// InitElGamal initializes ElGamal encryption and decryption with file parameters.
func InitElGamal(messageFile, publicKeyFile, privateKeyFile string) error {
	// Read message from file
	message, err := ReadStringFromFile(messageFile)
	if err != nil {
		return fmt.Errorf("error reading message from file: %v", err)
	}
	fmt.Println("Read from file:", message)

	// Generate ElGamal Key Pair
	bits := 256 // Change this to desired key size
	elGamalKeyPair, err := GenerateElGamalKeyPair(bits)
	if err != nil {
		return fmt.Errorf("error generating ElGamal key pair: %v", err)
	}

	// Convert message to big.Int
	messageInt := new(big.Int).SetBytes([]byte(message))

	// Encrypt the message using ElGamal
	c1, c2, err := EncryptElGamal(messageInt, elGamalKeyPair.PublicKey)
	if err != nil {
		return fmt.Errorf("error encrypting with ElGamal: %v", err)
	}

	// Decrypt the ciphertext using ElGamal
	decryptedMessage, err := DecryptElGamal(c1, c2, elGamalKeyPair.PrivateKey)
	if err != nil {
		return fmt.Errorf("error decrypting with ElGamal: %v", err)
	}

	// Write keys to files
	err = WriteElGamalKeysToFile(elGamalKeyPair, publicKeyFile, privateKeyFile)
	if err != nil {
		return fmt.Errorf("error writing ElGamal keys to files: %v", err)
	}

	// Print original and decrypted messages
	fmt.Println("Original message:", message)
	fmt.Println("Encrypted message (c1):", c1)
	fmt.Println("Encrypted message (c2):", c2)
	fmt.Println("Decrypted message:", string(decryptedMessage.Bytes()))

	return nil
}

func DecryptMessageWithPrivateKey(c1, c2, privateKeyFile string) error {
	// Read private key from file
	privateKey, err := ReadElGamalPrivateKeyFromFile(privateKeyFile)
	if err != nil {
		return fmt.Errorf("error reading private key from file: %v", err)
	}

	// Convert c1 and c2 to big.Int
	c1Int, ok := new(big.Int).SetString(c1, 10)
	if !ok {
		return fmt.Errorf("invalid value for c1")
	}
	c2Int, ok := new(big.Int).SetString(c2, 10)
	if !ok {
		return fmt.Errorf("invalid value for c2")
	}

	// Decrypt the ciphertext using ElGamal
	decryptedMessage, err := DecryptElGamal(c1Int, c2Int, privateKey)
	if err != nil {
		return fmt.Errorf("error decrypting with ElGamal: %v", err)
	}

	// Print decrypted message
	fmt.Println("Decrypted message:", string(decryptedMessage.Bytes()))

	return nil
}
