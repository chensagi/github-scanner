package main

import (
	"context"
	"fmt"
	"log"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/google/go-github/v69/github"
)

// GitHubClient is a reusable client instance
var GitHubClient *github.Client

// RepositoryPermissions stores structured permission data
type RepositoryPermissions struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	Source   string `json:"source"`
}

// RepositoryInfo stores structured repository data
type RepositoryInfo struct {
	Name          string                  `json:"name"`
	FullName      string                  `json:"full_name"`
	Owner         string                  `json:"owner"`
	Visibility    string                  `json:"visibility"`
	Private       bool                    `json:"private"`
	Description   string                  `json:"description"`
	RepoURL       string                  `json:"repo_url"`
	DefaultBranch string                  `json:"default_branch"`
	LastUpdated   string                  `json:"last_updated"`
	Permissions   []RepositoryPermissions `json:"permissions"`
	ScanResult    bool                    `json:"scan_result"` 
}

// Function to evaluate a Rego policy against input data
func evaluatePolicy(policy string, input interface{}) (bool, error) {
	ctx := context.Background()

	// Compile Rego policy
	r := rego.New(
		rego.Query("data.repository.allow"), // Query the `allow` rule
		rego.Module("repository.rego", policy),
		rego.Input(input),
	)

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to prepare rego query: %w", err)
	}

	// Run the evaluation
	rs, err := query.Eval(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to evaluate policy: %w", err)
	}

	// If policy result contains `allow = true`, return true
	if len(rs) > 0 && len(rs[0].Expressions) > 0 {
		result, ok := rs[0].Expressions[0].Value.(bool)
		if ok && result {
			return true, nil
		}
	}

	return false, nil
}

// InitGitHubClient initializes the GitHub client once
func InitGitHubClient() {
	if GitHubClient == nil {
		GitHubClient = getGitHubClient()
	}
}

// ScanOrganization retrieves repositories and their access details and evaluates them against a policy
func ScanOrganization(org string, policy string) {
	InitGitHubClient()
	ctx := context.Background()
	opt := &github.RepositoryListByOrgOptions{Type: "all"}
	var allRepos []*github.Repository

	// Fetch all repositories in the organization
	for {
		repos, resp, err := GitHubClient.Repositories.ListByOrg(ctx, org, opt)
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

	// Process each repository
	for _, repo := range allRepos {
		repoInfo := scanRepository(ctx, org, repo)

		// Evaluate repository against policy
		success, err := evaluatePolicy(policy, repoInfo)
		if err != nil {
			log.Printf("Error evaluating policy for %s: %v", repoInfo.FullName, err)
			repoInfo.ScanResult = false
		} else {
			repoInfo.ScanResult = success
		}

		// Print the results
		printRepositoryInfo(repoInfo)
	}
}

// scanRepository retrieves repository metadata and permissions
func scanRepository(ctx context.Context, org string, repo *github.Repository) RepositoryInfo {
	InitGitHubClient()

	repoDetails, _, err := GitHubClient.Repositories.Get(ctx, org, repo.GetName())
	if err != nil {
		log.Printf("Skipping %s due to error: %v", repo.GetName(), err)
		return RepositoryInfo{}
	}

	// Fetch permissions separately
	permissions := FetchRepositoryPermissions(ctx, repoDetails, org)

	// Normalize and return structured data
	return NormalizeRepoData(repoDetails, permissions)
}

// FetchRepositoryPermissions retrieves collaborator permissions for a repository
func FetchRepositoryPermissions(ctx context.Context, repo *github.Repository, org string) []RepositoryPermissions {
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()

	// Fetch repository collaborators
	collaborators, _, err := GitHubClient.Repositories.ListCollaborators(ctx, owner, repoName, nil)
	if err != nil {
		log.Printf("Error fetching collaborators for %s: %v", repoName, err)
		return nil
	}

	// Fetch teams with access to this repository
	teams, _, err := GitHubClient.Repositories.ListTeams(ctx, owner, repoName, nil)
	if err != nil {
		log.Printf("Error fetching teams for %s: %v", repoName, err)
	}

	// Map team members to their respective teams
	teamMembers := make(map[string]string) // user -> team
	for _, team := range teams {
		teamSlug := team.GetSlug()
		members, _, err := GitHubClient.Teams.ListTeamMembersBySlug(ctx, org, teamSlug, nil)
		if err != nil {
			log.Printf("Error fetching members for team %s: %v", teamSlug, err)
			continue
		}
		for _, member := range members {
			teamMembers[member.GetLogin()] = teamSlug
		}
	}

	// Extract permissions for each collaborator
	var permissions []RepositoryPermissions
	for _, collab := range collaborators {
		perm, _, err := GitHubClient.Repositories.GetPermissionLevel(ctx, owner, repoName, collab.GetLogin())
		if err != nil {
			log.Printf("Error fetching permissions for %s in %s: %v", collab.GetLogin(), repoName, err)
			continue
		}

		// Determine if the user has access via a team
		source := "user"
		if team, exists := teamMembers[collab.GetLogin()]; exists {
			source = "team:" + team
		}

		permissions = append(permissions, RepositoryPermissions{
			Username: collab.GetLogin(),
			Role:     perm.GetPermission(),
			Source:   source,
		})
	}
	return permissions
}

// NormalizeRepoData structures repository data, now with pre-fetched permissions
func NormalizeRepoData(repo *github.Repository, permissions []RepositoryPermissions) RepositoryInfo {
	return RepositoryInfo{
		Name:          repo.GetName(),
		FullName:      repo.GetFullName(),
		Owner:         repo.GetOwner().GetLogin(),
		Visibility:    repo.GetVisibility(),
		Private:       repo.GetPrivate(),
		Description:   repo.GetDescription(),
		RepoURL:       repo.GetHTMLURL(),
		DefaultBranch: repo.GetDefaultBranch(),
		LastUpdated:   repo.GetUpdatedAt().String(),
		Permissions:   permissions,
	}
}

// printRepositoryInfo displays structured repository data with scan result
func printRepositoryInfo(repo RepositoryInfo) {
	fmt.Printf("\nRepository: %s\n", repo.FullName)
	fmt.Printf("Visibility: %s\n", repo.Visibility)
	fmt.Printf("Private: %v\n", repo.Private)
	fmt.Printf("Owner: %s\n", repo.Owner)
	fmt.Printf("Default Branch: %s\n", repo.DefaultBranch)
	fmt.Printf("Last Updated: %s\n", repo.LastUpdated)
	fmt.Printf("Description: %s\n", repo.Description)
	fmt.Printf("Repository URL: %s\n", repo.RepoURL)

	// Show OPA Scan Result
	if repo.ScanResult {
		fmt.Println("OPA Scan Result: SUCCESS")
	} else {
		fmt.Println("OPA Scan Result: FAILURE")
	}

	fmt.Println("Permissions:")
	if len(repo.Permissions) == 0 {
		fmt.Println("  No collaborators found.")
	} else {
		for _, perm := range repo.Permissions {
			fmt.Printf("  - %s: %s (source: %s)\n", perm.Username, perm.Role, perm.Source)
		}
	}
	fmt.Println("--------------------------------------------------")
}