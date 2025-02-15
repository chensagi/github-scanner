package main

import (
	"context"
	"log"
	"os"

	"github.com/google/go-github/v69/github"
	"golang.org/x/oauth2"
)

// getGitHubClient initializes a GitHub API client
func getGitHubClient() *github.Client {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		log.Fatal("GITHUB_TOKEN is missing. Set it in .env")
	}

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(context.Background(), ts)

	return github.NewClient(tc)
}
