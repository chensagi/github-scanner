package main

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: No .env file found!")
	}
}

func main() {
	loadEnv()

	org := os.Getenv("ORG_NAME")
	if org == "" {
		log.Fatal("ORG_NAME is required in .env")
	}

	fmt.Println("Starting GitHub Scanner for org:", org)

	// Fetch repositories and scan them
	ScanOrganization(org)
}
