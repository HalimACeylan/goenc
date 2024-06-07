package asymmetric

import (
	"crypto/rand"
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
}

// GenerateElGamalKeyPair generates a new ElGamal key pair.
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
func DecryptElGamal(c1, c2 *big.Int, priv *ElGamalPrivateKey, p *big.Int) (*big.Int, error) {
	// Compute s = c1^x mod p
	s := new(big.Int).Exp(c1, priv.X, p)

	// Compute plaintext = (c2 * s^-1) mod p
	sInverse := new(big.Int).ModInverse(s, p)
	if sInverse == nil {
		return nil, fmt.Errorf("failed to compute modular inverse")
	}
	plainText := new(big.Int).Mod(new(big.Int).Mul(c2, sInverse), p)

	return plainText, nil
}

// WriteElGamalKeysToFile writes the ElGamal public and private keys to separate files.
// WriteElGamalKeysToFile writes the ElGamal public and private keys to separate files.
func WriteElGamalKeysToFile(keyPair *ElGamalKeyPair, publicKeyFile, privateKeyFile string) error {
	// Write public key to file
	err := ioutil.WriteFile(publicKeyFile, []byte(keyPair.PublicKey.String()), 0644)
	if err != nil {
		return fmt.Errorf("error writing public key to file: %v", err)
	}

	// Write private key to file
	err = ioutil.WriteFile(privateKeyFile, []byte(keyPair.PrivateKey.String()), 0644)
	if err != nil {
		return fmt.Errorf("error writing private key to file: %v", err)
	}

	return nil
}

// String method for ElGamalPublicKey to convert it to string format.
func (pub *ElGamalPublicKey) String() string {
	return fmt.Sprintf("P: %s\nG: %s\nY: %s\n", pub.P.String(), pub.G.String(), pub.Y.String())
}

// String method for ElGamalPrivateKey to convert it to string format.
func (priv *ElGamalPrivateKey) String() string {
	return fmt.Sprintf("X: %s\n", priv.X.String())
}

// InitElGamal generates an ElGamal key pair, encrypts and decrypts a message,
// and writes the keys to separate files.
func InitElGamal() {
	// Generate ElGamal Key Pair
	bits := 256 // Change this to desired key size
	elGamalKeyPair, err := GenerateElGamalKeyPair(bits)
	if err != nil {
		fmt.Println("Error generating ElGamal key pair:", err)
		return
	}

	// Original message
	message := new(big.Int).SetInt64(123456)

	// Encrypt the message using ElGamal
	c1, c2, err := EncryptElGamal(message, elGamalKeyPair.PublicKey)
	if err != nil {
		fmt.Println("Error encrypting with ElGamal:", err)
		return
	}

	// Decrypt the ciphertext using ElGamal
	decryptedMessage, err := DecryptElGamal(c1, c2, elGamalKeyPair.PrivateKey, elGamalKeyPair.PublicKey.P)
	if err != nil {
		fmt.Println("Error decrypting with ElGamal:", err)
		return
	}

	fmt.Println("Original message:", message)
	fmt.Println("Decrypted message:", decryptedMessage)

	// Write keys to files
	err = WriteElGamalKeysToFile(elGamalKeyPair, "ElgamalpublicKey", "ElgamalprivateKey")
	if err != nil {
		fmt.Println("Error writing ElGamal keys to files:", err)
		return
	}

	fmt.Println("ElGamal keys written to files: publicKey.json, privateKey.json")
}
