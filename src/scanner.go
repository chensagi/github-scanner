package main

import (
	"context"
	"fmt"
	"log"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/google/go-github/v69/github"
	pb "github-scanner/src/pb"
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
	ScanResult    string                  `json:"scan_result"` 
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

// ScanOrganizationForGRPC calls ScanOrganization and converts results for gRPC
func ScanOrganizationForGRPC(org string, policy string) []*pb.RepositoryInfo {
	scannedRepos := ScanOrganization(org, policy)
	var grpcRepos []*pb.RepositoryInfo

	for _, repo := range scannedRepos {
		pbRepoInfo := &pb.RepositoryInfo{
			Name:          repo.Name,
			FullName:      repo.FullName,
			Owner:         repo.Owner,
			Visibility:    repo.Visibility,
			Private:       repo.Private,
			Description:   repo.Description,
			RepoUrl:       repo.RepoURL,
			DefaultBranch: repo.DefaultBranch,
			LastUpdated:   repo.LastUpdated,
			ScanResult:    repo.ScanResult,
		}

		// Convert permissions
		for _, perm := range repo.Permissions {
			pbRepoInfo.Permissions = append(pbRepoInfo.Permissions, &pb.RepositoryPermissions{
				Username: perm.Username,
				Role:     perm.Role,
				Source:   perm.Source,
			})
		}

		grpcRepos = append(grpcRepos, pbRepoInfo)
	}

	return grpcRepos
}

func ScanOrganization(org string, policy string) []RepositoryInfo {
	InitGitHubClient()
	ctx := context.Background()
	opt := &github.RepositoryListByOrgOptions{Type: "all"}
	var allRepos []*github.Repository
	var scannedRepos []RepositoryInfo

	log.Printf("Fetching repositories for organization: %s", org)

	// Fetch all repositories in the organization
	for {
		repos, resp, err := GitHubClient.Repositories.ListByOrg(ctx, org, opt)
		if err != nil {
			log.Fatalf("Error fetching repositories for %s: %v", org, err)
		}

		allRepos = append(allRepos, repos...)
		log.Printf("Fetched %d repositories so far...", len(allRepos))

		if resp.NextPage == 0 {
			log.Println("No more pages to fetch.")
			break
		}
		opt.Page = resp.NextPage
	}

	log.Printf("Total repositories found: %d", len(allRepos))

	// Process each repository
	for _, repo := range allRepos {
		repoInfo := scanRepository(ctx, org, repo)
		log.Printf("Processing repository: %s", repoInfo.FullName)

		// Evaluate repository against policy
		success, err := evaluatePolicy(policy, repoInfo)
		if err != nil {
			log.Printf("Error evaluating policy for %s: %v", repoInfo.FullName, err)
			repoInfo.ScanResult = err.Error() // Assign error message as ScanResult
		} else if success {
			repoInfo.ScanResult = "Success"
		} else {
			repoInfo.ScanResult = "Failure"
		}

		// Store in list instead of printing immediately
		scannedRepos = append(scannedRepos, repoInfo)
	}

	log.Println("Scan complete. Returning results.")
	return scannedRepos
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

func printRepositoryInfo(repo RepositoryInfo) {
	fmt.Printf("\nRepository: %-30s | Owner: %-15s | Visibility: %-10s | Scan Result: %-10s\n",
		repo.FullName, repo.Owner, repo.Visibility, repo.ScanResult)

	fmt.Printf("   URL: %s\n", repo.RepoURL)
	fmt.Printf("   Description: %s\n", repo.Description)
	fmt.Printf("   Last Updated: %s\n", repo.LastUpdated)
	fmt.Printf("   Default Branch: %s\n", repo.DefaultBranch)

	// Print permissions
	fmt.Println("   Permissions:")
	if len(repo.Permissions) == 0 {
		fmt.Println("   - No collaborators found.")
	} else {
		for _, perm := range repo.Permissions {
			fmt.Printf("   - User: %-20s | Role: %-10s | Source: %s\n", perm.Username, perm.Role, perm.Source)
		}
	}
	fmt.Println("------------------------------------------------------------")
}