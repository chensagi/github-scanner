package main

import (
    "context"
    "log"
    "os"
    "sync"

    "github.com/google/go-github/v69/github"
    "golang.org/x/oauth2"
)

var (
    gitHubClient     *github.Client
    gitHubClientOnce sync.Once
)

func getGitHubClient() *github.Client {
    gitHubClientOnce.Do(func() {
        token := os.Getenv("GITHUB_TOKEN")
        if token == "" {
            log.Fatal("GITHUB_TOKEN is missing. Set it in your environment.")
        }

        // Initialize a new OAuth2 client using the GitHub token
        ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
        tc := oauth2.NewClient(context.Background(), ts)

        // Create and store the GitHub client
        gitHubClient = github.NewClient(tc)
        log.Println("Initialized GitHub client.")
    })
    return gitHubClient
}
