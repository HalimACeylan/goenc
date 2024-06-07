package symmetrics

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

// GenerateAESKey generates a new AES key of the specified length.
func GenerateAESKey(length int) ([]byte, error) {
	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptAES encrypts plaintext using AES-GCM.
func EncryptAES(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAES decrypts ciphertext using AES-GCM.
func DecryptAES(key []byte, encodedCiphertext string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// WriteKeyToFile writes the AES key to a file.
func WriteKeyToFile(key []byte, filename string) error {
	return ioutil.WriteFile(filename, key, 0644)
}

// ReadKeyFromFile reads the AES key from a file.
func ReadKeyFromFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// EncryptFile encrypts a file and writes the ciphertext to another file.
func EncryptFile(key []byte, inputFile, outputFile string) error {
	plaintext, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return err
	}

	ciphertext, err := EncryptAES(key, plaintext)
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

	plaintext, err := DecryptAES(key, string(ciphertext))
	if err != nil {
		return err
	}

	return ioutil.WriteFile(outputFile, []byte(plaintext), 0644)
}
func InitAES(messageFile, KeyFile string) {
	// Generate a new AES key
	key, err := GenerateAESKey(32) // 256-bit key
	if err != nil {
		fmt.Println("Error generating AES key:", err)
		return
	}

	// Save the key to a file
	err = WriteKeyToFile(key, KeyFile)
	if err != nil {
		fmt.Println("Error writing AES key to file:", err)
		return
	}

	// Read the key from the file
	key, err = ReadKeyFromFile(KeyFile)
	if err != nil {
		fmt.Println("Error reading AES key from file:", err)
		return
	}

	// Encrypt a message
	message, err := os.ReadFile(messageFile)
	if err != nil {
		fmt.Println("Error reading message file:", err)
		return
	}
	encryptedMessage, err := EncryptAES(key, message)
	if err != nil {
		fmt.Println("Error encrypting message:", err)
		return
	}
	fmt.Println("Encrypted Message:", encryptedMessage)

	// Decrypt the message
	decryptedMessage, err := DecryptAES(key, encryptedMessage)
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return
	}
	fmt.Println("Decrypted Message:", decryptedMessage)

	// Encrypt a file
	inputFile := messageFile
	encryptedFile := "message.enc"
	err = EncryptFile(key, inputFile, encryptedFile)
	if err != nil {
		fmt.Println("Error encrypting file:", err)
		return
	}
	fmt.Println("File encrypted successfully")

	// Decrypt the file
	decryptedFile := "message.dec"
	err = DecryptFile(key, encryptedFile, decryptedFile)
	if err != nil {
		fmt.Println("Error decrypting file:", err)
		return
	}
	fmt.Println("File decrypted successfully")
}
