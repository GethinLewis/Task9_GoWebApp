package initializers

import (
	"log"

	"github.com/joho/godotenv"
)

func LoadEnvVariables() {
	var err error = godotenv.Load(".env")

	if err != nil {
		log.Fatal("Error loading .env file")
	}
}
