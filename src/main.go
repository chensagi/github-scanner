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

	// Example Rego policy: Ensure private repos have an admin
	policy := `
		package repository
		import rego.v1

		default allow = false

		allow if {
			input.visibility == "private"
			some i
			input.permissions[i].role == "admin"
		}
	`

	// Fetch repositories and scan them
	ScanOrganization(org, policy)

	fmt.Println("Starting gRPC Server for GitHub Scanner (Org:", org, ")")

	// Start the gRPC server
	StartGRPCServer("50051")
}
