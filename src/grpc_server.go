package main

import (
	"context"
	"log"
	"net"
	"os"
	"google.golang.org/grpc"
	pb "github-scanner/src/pb"
)

// Server struct for gRPC service
type Server struct {
	pb.UnimplementedPolicyServiceServer
}

// ScanRepositories triggers the GitHub scanner and returns repository results
func (s *Server) ScanRepositories(ctx context.Context, req *pb.PolicyRequest) (*pb.PolicyResponse, error) {
	log.Println("Received gRPC request to scan repositories...")

	// Initialize GitHub client
	InitGitHubClient()

	// Get organization name from environment
	org := GetOrgNameFromEnv()
	if org == "" {
		return &pb.PolicyResponse{Error: "ORG_NAME environment variable is missing"}, nil
	}

	// Scan organization and collect results
	repositories := ScanOrganizationForGRPC(org, req.Policy)

	// Return structured response
	return &pb.PolicyResponse{Repositories: repositories}, nil
}

// StartGRPCServer initializes and starts the gRPC server
func StartGRPCServer(port string) {
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterPolicyServiceServer(grpcServer, &Server{})

	log.Printf("gRPC server running on port %s...", port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

func GetOrgNameFromEnv() string {
	org := os.Getenv("ORG_NAME")
	if org == "" {
		log.Fatal("ORG_NAME is required in .env")
	}
	return org
}
