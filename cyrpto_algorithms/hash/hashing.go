package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io/ioutil"
)

// GenerateMD5Hash generates an MD5 hash of the input data.
func GenerateMD5Hash(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

// GenerateSHA1Hash generates a SHA-1 hash of the input data.
func GenerateSHA1Hash(data []byte) string {
	hash := sha1.Sum(data)
	return hex.EncodeToString(hash[:])
}

// GenerateSHA256Hash generates a SHA-256 hash of the input data.
func GenerateSHA256Hash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// GenerateSHA512Hash generates a SHA-512 hash of the input data.
func GenerateSHA512Hash(data []byte) string {
	hash := sha512.Sum512(data)
	return hex.EncodeToString(hash[:])
}

// ReadFile reads the content of the file specified by the filename.
func ReadFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// WriteHashToFile writes the hash to a file specified by the filename.
func WriteHashToFile(hash, filename string) error {
	return ioutil.WriteFile(filename, []byte(hash), 0644)
}

// GenerateAndSaveHash generates a hash of the file content using the specified hash function and saves it to a file.
func GenerateAndSaveHash(hashFunc func(data []byte) string, inputFile, outputFile string) error {
	data, err := ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	hash := hashFunc(data)
	if err := WriteHashToFile(hash, outputFile); err != nil {
		return fmt.Errorf("error writing hash to file: %w", err)
	}

	return nil
}

// GenerateHashFromString generates a hash of the input string using the specified hash function.
func GenerateHashFromString(hashFunc func(data []byte) string, input string) string {
	data := []byte(input)
	return hashFunc(data)
}
