package main

import (
	"crypto/rand"
	"errors"
	"fmt"
)

func generateKey(length int, suffix string) (string, error) {
	if length <= len(suffix) {
		return "", errors.New("length must be greater than suffix length")
	}

	key := make([]byte, length-len(suffix))
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x%s", key, suffix), nil
}

func main() {
	key, err := generateKey(16, "xyz")
	if err != nil {
		fmt.Println("Error generating key:", err)
		return
	}
	fmt.Println("Generated key:", key)
}