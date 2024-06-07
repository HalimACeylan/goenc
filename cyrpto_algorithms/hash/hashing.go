package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
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
func InitHashing(inputFile, md5File, sha1File, sha256File, sha512File string) {
	// Generate and save MD5 hash of file
	if err := GenerateAndSaveHash(GenerateMD5Hash, inputFile, md5File); err != nil {
		log.Fatalf("Error generating MD5 hash: %v", err)
	}
	fmt.Println("MD5 hash of file saved to:", md5File)

	// Generate and save SHA-1 hash of file
	if err := GenerateAndSaveHash(GenerateSHA1Hash, inputFile, sha1File); err != nil {
		log.Fatalf("Error generating SHA-1 hash: %v", err)
	}
	fmt.Println("SHA-1 hash of file saved to:", sha1File)

	// Generate and save SHA-256 hash of file
	if err := GenerateAndSaveHash(GenerateSHA256Hash, inputFile, sha256File); err != nil {
		log.Fatalf("Error generating SHA-256 hash: %v", err)
	}
	fmt.Println("SHA-256 hash of file saved to:", sha256File)

	// Generate and save SHA-512 hash of file
	if err := GenerateAndSaveHash(GenerateSHA512Hash, inputFile, sha512File); err != nil {
		log.Fatalf("Error generating SHA-512 hash: %v", err)
	}
	fmt.Println("SHA-512 hash of file saved to:", sha512File)
}

func InitStringHashing(inputString string) {
	// Generate and print MD5 hash of string
	md5Hash := GenerateHashFromString(GenerateMD5Hash, inputString)
	fmt.Println("MD5 hash of string:", md5Hash)

	// Generate and print SHA-1 hash of string
	sha1Hash := GenerateHashFromString(GenerateSHA1Hash, inputString)
	fmt.Println("SHA-1 hash of string:", sha1Hash)

	// Generate and print SHA-256 hash of string
	sha256Hash := GenerateHashFromString(GenerateSHA256Hash, inputString)
	fmt.Println("SHA-256 hash of string:", sha256Hash)

	// Generate and print SHA-512 hash of string
	sha512Hash := GenerateHashFromString(GenerateSHA512Hash, inputString)
	fmt.Println("SHA-512 hash of string:", sha512Hash)
}
