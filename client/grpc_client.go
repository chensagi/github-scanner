package main

import (
	"context"
	"fmt"
	"time"
	"log"
	"strings"
	"encoding/json"
	pb "github-scanner/src/pb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	serverAddress = "localhost"
	serverPort    = "50051"
	maxRetries    = 10               // Maximum number of retries
	retryInterval = 2 * time.Second  // Wait time between retries
	timeoutInSeconds = 5
)

var grpcClient pb.PolicyServiceClient

type PolicySummary struct {
    Policy         string
    Error          bool
    ErrorMessage   string
    Success        bool
    FailureCount   int
}

// List of Rego policies
var policies = []string{
	// Policy 1: Allow access if the repository is private and has an admin
	`
	package repository
	import rego.v1

	default allow = false

	allow if {
		input.private == true
		some i
		input.permissions[i].role == "admin"
	}
	`, 

	// Policy 2: Allow access if the repository owner is "Chensagics"
	`
	package repository
	import rego.v1

	default allow = false

	allow if {
		input.owner == "Chensagics"
	}
	`, 

	// Policy 3: Allow access if the repository is public and the user has "write" permission
	`
	package repository
	import rego.v1

	default allow = false

	allow if {
		input.private == false
		some i
		input.permissions[i].role == "write"
	}
	`, 

	// Policy 4: Allow access if the user belongs to a team that has repository permissions
	`
	package repository
	import rego.v1

	default allow = false

	# Check if user has access via team permissions
	allow if {
		some i
		input.permissions[i].source == "team"
		input.permissions[i].username == input.user.username
		input.permissions[i].role == "write"
	}

	# Check if user has admin role via team membership
	allow if {
		some i
		input.permissions[i].source == "team"
		input.permissions[i].username == input.user.username
		input.permissions[i].role == "admin"
	}
	`,
	// Policy 5: Deny access if the repository is private and the user is not the owner
	`
	package repository
	import rego.v1

	default allow = false
	default deny = false

	deny if {
		input.private == true
		input.user.username != input.owner
	}
	`, 

	// Policy 6: Allow access if the repository is public and the user has at least "read" permission
	`
	package repository
	import rego.v1

	default allow = false

	allow if {
		input.private == false
		some i
		input.permissions[i].username == input.user.username
		input.permissions[i].role == "read"
	}
	`, 

	// Policy 7: Deny access to users who belong to the "gang" team, regardless of role
	`
	package repository
	import rego.v1

	default allow = false
	default deny = false

	deny if {
		some i
		input.permissions[i].username == input.user.username
		startswith(input.permissions[i].source, "team:gang")
	}
	`,
	// Policy 8: Allow access if the repository is public
	`
	package repository
	import rego.v1

	default allow = false

	allow if {
		input.private == false
	}
	`,
}

func main() {
	conn, err := connectToServer()
	if err != nil {
		log.Fatalf("Error connecting to server: %v", err)
	}
	defer conn.Close()

	// Invoke the policy scan
	summaries := invokePolicyScan(grpcClient)

	// Print final summary
	printFinalSummary(summaries)
}

func connectToServer() (*grpc.ClientConn, error) {
	var clientConn *grpc.ClientConn
	var err error

	for i := 0; i < maxRetries; i++ {
		clientConn, err = grpc.Dial(fmt.Sprintf("%s:%s", serverAddress, serverPort),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		
		if err == nil {
			log.Println("Connected to gRPC server.")
			grpcClient = pb.NewPolicyServiceClient(clientConn)
			return clientConn, nil
		}

		log.Printf("Failed to connect to server (attempt %d/%d): %v", i+1, maxRetries, err)
		time.Sleep(retryInterval)
	}

	return nil, fmt.Errorf("failed to connect to server after %d retries", maxRetries)
}

func invokePolicyScan(client pb.PolicyServiceClient) []PolicySummary {
    if client == nil {
        log.Fatalf("gRPC client is not initialized")
    }

    var summaries []PolicySummary

    for _, policy := range policies {
        log.Printf("Scanning with policy:\n%s", policy)

        ctx, cancel := context.WithTimeout(context.Background(), timeoutInSeconds*time.Second)
        defer cancel()

        res, err := client.ScanRepositories(ctx, &pb.PolicyRequest{Policy: policy})
        if err != nil {
            log.Printf("Error calling ScanRepositories: %v", err)
            summaries = append(summaries, PolicySummary{
                Policy:       strings.TrimSpace(policy),
                Error:        true,
                ErrorMessage: err.Error(),
            })
            continue // Skip to next policy if there's an error
        }

        if res == nil {
            log.Printf("Received nil response for policy: %s", policy)
            summaries = append(summaries, PolicySummary{
                Policy:       strings.TrimSpace(policy),
                Error:        true,
                ErrorMessage: "Nil response from server",
            })
            continue
        }

        // Debug: Print full gRPC response
        resJSON, _ := json.MarshalIndent(res, "", "  ")
        log.Printf("Full gRPC Response:\n%s", resJSON)

        summary := PolicySummary{
            Policy:       strings.TrimSpace(policy),
            FailureCount: 0,
        }

        // Check if gRPC response contains an error message
        if res.Error != "" {
            log.Printf("Server error for policy:\n%s\nError: %v", policy, res.Error)
            summary.Error = true
            summary.ErrorMessage = res.Error
        } else {
            // Process repositories and tally failures
            for _, repo := range res.Repositories {
                result := strings.ToLower(repo.ScanResult)

                switch result {
                case "failure":
                    summary.FailureCount++
                case "success":
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
            // If there's an overall policy error
            fmt.Printf("Result: ERROR - %s\n", summary.ErrorMessage)
            totalError++
        } else if summary.FailureCount > 0 {
            // If there are any repository failures under this policy
            fmt.Printf("Result: FAILURE (Number of failing repos: %d)\n", summary.FailureCount)
            totalFailure++
        } else if summary.Success {
            // If the policy has at least one success and no failures
            fmt.Println("Result: SUCCESS")
            totalSuccess++
        } else {
            // If there's no error, no failures, and no success reported
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