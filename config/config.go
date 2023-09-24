package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

func GenerateRandomString(length int) (string, error) {
  randomBytes := make([]byte, length)
  _, err := rand.Read(randomBytes)
  if err != nil {
    return "", err
  }
  randomString := hex.EncodeToString(randomBytes)
  return randomString, nil
}

func Config(key string) string {
  err := godotenv.Load(".env")
  if err != nil {
    fmt.Println("Error loading .env file")
  }
  return os.Getenv(key)
}
