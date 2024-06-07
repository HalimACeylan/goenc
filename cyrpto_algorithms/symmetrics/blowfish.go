package symmetric

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/blowfish"
)

// GenerateBlowfishKey generates a new Blowfish key of the specified length.
func GenerateBlowfishKey(length int) ([]byte, error) {
	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptBlowfish encrypts plaintext using Blowfish.
func EncryptBlowfish(key, plaintext []byte) (string, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, blowfish.BlockSize+len(plaintext))
	iv := ciphertext[:blowfish.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[blowfish.BlockSize:], plaintext)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptBlowfish decrypts ciphertext using Blowfish.
func DecryptBlowfish(key []byte, encodedCiphertext string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return "", err
	}

	block, err := blowfish.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < blowfish.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:blowfish.BlockSize]
	ciphertext = ciphertext[blowfish.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

// WriteKeyToFile writes the Blowfish key to a file.
func WriteKeyToFile(key []byte, filename string) error {
	return ioutil.WriteFile(filename, key, 0644)
}

// ReadKeyFromFile reads the Blowfish key from a file.
func ReadKeyFromFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// EncryptFile encrypts a file and writes the ciphertext to another file.
func EncryptFile(key []byte, inputFile, outputFile string) error {
	plaintext, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return err
	}

	ciphertext, err := EncryptBlowfish(key, plaintext)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(outputFile, []byte(ciphertext), 0644)
}

// DecryptFile decrypts a file and writes the plaintext to another file.
func DecryptFile(key []byte, inputFile, outputFile string) error {
	ciphertext, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return err
	}

	plaintext, err := DecryptBlowfish(key, string(ciphertext))
	if err != nil {
		return err
	}

	return ioutil.WriteFile(outputFile, []byte(plaintext), 0644)
}
func InitBlowfish(messageFile, keyFile, encryptedFile, decryptedFile string) {
	// Generate a new Blowfish key
	key, err := GenerateBlowfishKey(16) // Blowfish key length can vary
	if err != nil {
		fmt.Println("Error generating Blowfish key:", err)
		return
	}

	// Save the key to a file
	err = WriteKeyToFile(key, keyFile)
	if err != nil {
		fmt.Println("Error writing Blowfish key to file:", err)
		return
	}

	// Read the key from the file
	key, err = ReadKeyFromFile(keyFile)
	if err != nil {
		fmt.Println("Error reading Blowfish key from file:", err)
		return
	}

	// Read the message from the file
	message, err := os.ReadFile(messageFile)
	if err != nil {
		fmt.Println("Error reading message file:", err)
		return
	}

	// Encrypt the message
	encryptedMessage, err := EncryptBlowfish(key, message)
	if err != nil {
		fmt.Println("Error encrypting message:", err)
		return
	}
	fmt.Println("Encrypted Message:", encryptedMessage)

	// Write the encrypted message to the encrypted file
	err = ioutil.WriteFile(encryptedFile, []byte(encryptedMessage), 0644)
	if err != nil {
		fmt.Println("Error writing encrypted message to file:", err)
		return
	}

	// Decrypt the message
	decryptedMessage, err := DecryptBlowfish(key, encryptedMessage)
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return
	}
	fmt.Println("Decrypted Message:", decryptedMessage)

	// Write the decrypted message to the decrypted file
	err = ioutil.WriteFile(decryptedFile, []byte(decryptedMessage), 0644)
	if err != nil {
		fmt.Println("Error writing decrypted message to file:", err)
		return
	}

	fmt.Println("File encryption and decryption complete")
}
