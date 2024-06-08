package symmetric

import (
	cryptoAES "crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
)

// AES struct to hold AES related fields
type AES struct {
	publicKey cipher.Block
	mode      cipher.AEAD
	nonce     []byte
}

// SetPublicKey sets the AES public key
func (aes *AES) SetPublicKey(key []byte) {
	var err error
	aes.publicKey, err = cryptoAES.NewCipher(key)
	if err != nil {
		log.Fatalf("Error during the Public Key Generating reason: %s", err.Error())
	}
}

// selectMode selects the AES mode
func (aes *AES) selectMode() {
	var err error
	aes.mode, err = cipher.NewGCM(aes.publicKey)
	if err != nil {
		log.Fatalf("Error during the Selecting AES Mode reason: %s", err.Error())
	}
}

// createNonce creates a nonce
func (aes *AES) createNonce() {
	aes.nonce = make([]byte, aes.mode.NonceSize())
	if _, err := io.ReadFull(rand.Reader, aes.nonce); err != nil {
		log.Fatalf("Error during the generating AES Nonce reason: %s", err)
	}
}

// EncryptAES encrypts the plaintext
func (aes *AES) EncryptAES(plaintext []byte) []byte {
	aes.selectMode()
	aes.createNonce()
	return aes.mode.Seal(aes.nonce, aes.nonce, plaintext, nil)
}

// DecryptAES decrypts the ciphertext
func (aes *AES) DecryptAES(ciphertext []byte) ([]byte, error) {
	aes.selectMode()
	nonceSize := aes.mode.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aes.mode.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("error during decryption: %s", err.Error())
	}
	return plaintext, nil
}

func AESWriteKeyToFile(key []byte, filename string) error {
	encodedKey := base64.StdEncoding.EncodeToString(key)
	return ioutil.WriteFile(filename, []byte(encodedKey), 0644)
}

// ReadKeyFromFile reads the AES key from a file and decodes it from base64
func AESReadKeyFromFile(filename string) ([]byte, error) {
	encodedKey, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading AES key from file: %v", err)
	}
	key, err := base64.StdEncoding.DecodeString(string(encodedKey))
	if err != nil {
		return nil, fmt.Errorf("error decoding AES key from base64: %v", err)
	}
	return key, nil
}

// GenerateAESKey generates a new AES key of the specified length
func GenerateAESKey(length int) ([]byte, error) {
	if length != 16 && length != 24 && length != 32 {
		return nil, fmt.Errorf("invalid key size %d: must be 16, 24, or 32 bytes", length)
	}
	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// ReadFromFile reads data from a file
func ReadFromFile(filename string) ([]byte, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}
	return data, nil
}

// GenerateAESKeyFiles generates an AES key and writes it to a file
func GenerateAESKeyFiles() error {
	key, err := GenerateAESKey(32)
	if err != nil {
		return err
	}
	fmt.Println("AES key (base64):", base64.StdEncoding.EncodeToString(key))
	err = AESWriteKeyToFile(key, "AES_key.txt")
	if err != nil {
		return err
	}
	fmt.Println("AES key generation complete")
	return nil
}

// AESEncryptFile encrypts the contents of a file using AES
func AESEncryptFile(inputFile, keyFile string) error {
	key, err := AESReadKeyFromFile(keyFile)
	if err != nil {
		fmt.Printf("error reading AES key from file: %v", err)
	}

	plaintext, err := ReadFromFile(inputFile)
	if err != nil {
		return fmt.Errorf("error reading message from file: %v", err)
	}

	aes := AES{}
	aes.SetPublicKey(key)
	encryptedText := aes.EncryptAES(plaintext)

	err = ioutil.WriteFile("AES_enc_message.txt", encryptedText, 0644)
	if err != nil {
		return fmt.Errorf("error writing encrypted data to file: %v", err)
	}

	return nil
}

// AESDecryptFile decrypts the contents of a file using AES
func AESDecryptFile(inputFile, keyFile string) error {
	key, err := AESReadKeyFromFile(keyFile)
	if err != nil {
		return fmt.Errorf("error reading AES key from file: %v", err)
	}

	encryptedText, err := ReadFromFile(inputFile)
	if err != nil {
		return fmt.Errorf("error reading encrypted data from file: %v", err)
	}

	aes := AES{}
	aes.SetPublicKey(key)
	decryptedText, err := aes.DecryptAES(encryptedText)
	if err != nil {
		return fmt.Errorf("error decrypting file: %v", err)
	}

	fmt.Printf("Decrypted message: %s\n", decryptedText)

	return nil
}
