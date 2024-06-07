package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
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
