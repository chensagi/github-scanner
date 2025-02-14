package main

import (
	"context"
	"fmt"
	"log"

	"github.com/google/go-github/v55/github"
)

// RepositoryInfo defines a structured format for repository data
type RepositoryInfo struct {
	Name          string            `json:"name"`
	FullName      string            `json:"full_name"`
	Owner         string            `json:"owner"`
	Visibility    string            `json:"visibility"`
	Private       bool              `json:"private"`
	Stars         int               `json:"stars"`
	Forks         int               `json:"forks"`
	Watchers      int               `json:"watchers"`
	Description   string            `json:"description"`
	RepoURL       string            `json:"repo_url"`
	DefaultBranch string            `json:"default_branch"`
	LastUpdated   string            `json:"last_updated"`
	Permissions   map[string]bool   `json:"permissions"`
}

// NormalizeRepoData converts GitHub API response into structured RepositoryInfo
func NormalizeRepoData(repo *github.Repository) RepositoryInfo {
	return RepositoryInfo{
		Name:          repo.GetName(),
		FullName:      repo.GetFullName(),
		Owner:         repo.GetOwner().GetLogin(),
		Visibility:    repo.GetVisibility(),
		Private:       repo.GetPrivate(),
		Stars:         repo.GetStargazersCount(),
		Forks:         repo.GetForksCount(),
		Watchers:      repo.GetWatchersCount(),
		Description:   repo.GetDescription(),
		RepoURL:       repo.GetHTMLURL(),
		DefaultBranch: repo.GetDefaultBranch(),
		LastUpdated:   repo.GetUpdatedAt().String(),
		Permissions:   repo.GetPermissions(),
	}
}

// ScanOrganization retrieves and processes repositories in an organization
func ScanOrganization(org string) {
	client := getGitHubClient()
	ctx := context.Background()
	opt := &github.RepositoryListByOrgOptions{Type: "all"}
	var allRepos []*github.Repository

	for {
		repos, resp, err := client.Repositories.ListByOrg(ctx, org, opt)
		if err != nil {
			log.Fatalf("Error fetching repositories for %s: %v", org, err)
		}

		allRepos = append(allRepos, repos...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	fmt.Printf("Found %d repositories in organization: %s\n", len(allRepos), org)

	for _, repo := range allRepos {
		repoInfo := scanRepository(org, repo)
		printRepositoryInfo(repoInfo)
	}
}

// scanRepository retrieves details and normalizes repository data
func scanRepository(org string, repo *github.Repository) RepositoryInfo {
	client := getGitHubClient()
	ctx := context.Background()

	repoDetails, _, err := client.Repositories.Get(ctx, org, repo.GetName())
	if err != nil {
		log.Printf("Skipping %s due to error: %v", repo.GetName(), err)
		return RepositoryInfo{}
	}

	return NormalizeRepoData(repoDetails)
}

// printRepositoryInfo displays structured repository data
func printRepositoryInfo(repo RepositoryInfo) {
	fmt.Printf("\nRepository: %s\n", repo.FullName)
	fmt.Printf("Visibility: %s\n", repo.Visibility)
	fmt.Printf("Private: %v\n", repo.Private)
	fmt.Printf("Owner: %s\n", repo.Owner)
	fmt.Printf("Stars: %d | Forks: %d | Watchers: %d\n", repo.Stars, repo.Forks, repo.Watchers)
	fmt.Printf("Default Branch: %s\n", repo.DefaultBranch)
	fmt.Printf("Last Updated: %s\n", repo.LastUpdated)
	fmt.Printf("Description: %s\n", repo.Description)
	fmt.Printf("Repository URL: %s\n", repo.RepoURL)

	fmt.Println("Permissions:")
	for perm, hasAccess := range repo.Permissions {
		fmt.Printf("  - %s: %v\n", perm, hasAccess)
	}
	fmt.Println("--------------------------------------------------")
}
