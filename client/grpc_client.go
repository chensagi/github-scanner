package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
	"encoding/json"
	pb "github-scanner/src/pb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	timeoutInSeconds = 3
	serverAddress    = "localhost"
	serverPort       = "50051"
)

type PolicySummary struct {
	Policy      string
	Success     bool  
	Failure     bool   
	Error       bool  
	ErrorMessage string 
}

// List of Rego policies
var policies = []string{
	`
	package repository
	import rego.v1

	default allow = false

	allow if {
		input.visibility == "private"
		some i
		input.permissions[i].role == "admin"
	}
	`, // Policy 1

	`
	package repository
	import rego.v1

	default allow = false

	allow if {
		input.owner == "Chensagics"
	}
	`, // Policy 2

	`
	package repository
	import rego.v1

	default allow = false

	allow if {
		input.private == false
		some i
		input.permissions[i].role == "maintainer"
	}
	`, // Policy 3
	`fdefsdfsd`,
}

func main() {
	// Connect to the gRPC server
	client, conn := connectToServer()
	defer conn.Close()

	// Invoke the policy scan and collect results
	summaries := invokePolicyScan(client)

	// Print final summary
	printFinalSummary(summaries)
}

// connectToServer establishes a gRPC client
func connectToServer() (pb.PolicyServiceClient, *grpc.ClientConn) {
	// Create a new gRPC client connection
	clientConn, err := grpc.NewClient(fmt.Sprintf("%s:%s", serverAddress, serverPort),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect to gRPC server at %s:%s: %v", serverAddress, serverPort, err)
	}

	log.Println("Connected to gRPC server.")

	// Create and return the gRPC client
	return pb.NewPolicyServiceClient(clientConn), clientConn
}

func invokePolicyScan(client pb.PolicyServiceClient) []PolicySummary {
	var summaries []PolicySummary

	for _, policy := range policies {
		log.Printf("Scanning with policy:\n%s", policy)

		ctx, cancel := context.WithTimeout(context.Background(), timeoutInSeconds*time.Second)
		defer cancel()

		// Call the gRPC function and get the response
		res, err := client.ScanRepositories(ctx, &pb.PolicyRequest{Policy: policy})

		// Debug: Print full gRPC response
		if res != nil {
			resJSON, _ := json.MarshalIndent(res, "", "  ")
			log.Printf("Full gRPC Response:\n%s", resJSON)
		} else {
			log.Println("Response is nil")
		}

		summary := PolicySummary{Policy: strings.TrimSpace(policy)}

		// Detect error from res.Error OR from scan results that contain an error message
		errorMessage := ""
		if err != nil {
			errorMessage = err.Error()
		} else if res.Error != "" {
			errorMessage = res.Error
		}

		// Check if any repository's scan result contains an error
		for _, repo := range res.Repositories {
			if strings.Contains(strings.ToLower(repo.ScanResult), "error") || 
			   strings.Contains(strings.ToLower(repo.ScanResult), "failed") {
				errorMessage = fmt.Sprintf("%s | Scan Result: %s", errorMessage, repo.ScanResult)
				break
			}
		}

		if errorMessage != "" {
			log.Printf("Error processing policy:\n%s\nError: %v", policy, errorMessage)
			summary.Error = true
			summary.ErrorMessage = errorMessage
		} else {
			// Process repositories and check their scan results
			for _, repo := range res.Repositories {
				result := strings.ToLower(repo.ScanResult)

				if result == "failure" {
					summary.Failure = true
				} else if result == "success" {
					summary.Success = true
				}
			}
		}

		summaries = append(summaries, summary)
	}

	return summaries
}

func printFinalSummary(summaries []PolicySummary) {
	totalSuccess := 0
	totalFailure := 0
	totalError := 0

	fmt.Println("\nFinal Summary of All Policies:")
	fmt.Println("------------------------------------------------------------")

	for _, summary := range summaries {
		fmt.Println("Policy:")
		fmt.Println(summary.Policy)

		if summary.Error {
			fmt.Printf("Result: ERROR - %s\n", summary.ErrorMessage)
			totalError++
		} else if summary.Failure {
			fmt.Println("Result: FAILURE")
			totalFailure++
		} else if summary.Success {
			fmt.Println("Result: SUCCESS")
			totalSuccess++
		} else {
			fmt.Println("Result: ERROR (NO MATCHING CONDITION)")
			totalError++
		}

		fmt.Println("------------------------------------------------------------")
	}

	// Print final count summary
	fmt.Printf("Total Policies: %d\n", len(summaries))
	fmt.Printf("Success: %d, Failure: %d, Error: %d\n", totalSuccess, totalFailure, totalError)
	log.Println("Policy scanning completed.")
}