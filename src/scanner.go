package main

import (
    "context"
    "fmt"
    "log"
    "strings"

    "github.com/google/go-github/v69/github"
    "github.com/open-policy-agent/opa/v1/rego"
    pb "github-scanner/src/pb"
)

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

// ScanOrganization fetches repositories and evaluates them against the policy
func ScanOrganization(org string, policy string) []RepositoryInfo {
    client := getGitHubClient() // 1) Obtain the client from github_client.go

    ctx := context.Background()
    opt := &github.RepositoryListByOrgOptions{Type: "all"}
    var allRepos []*github.Repository
    var scannedRepos []RepositoryInfo

    log.Printf("Fetching repositories for organization: %s", org)

    // Fetch all repositories in the organization
    for {
        repos, resp, err := client.Repositories.ListByOrg(ctx, org, opt)
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
        repoInfo := scanRepository(ctx, org, repo, client) // pass client around
        log.Printf("Processing repository: %s", repoInfo.FullName)

        // Evaluate the repository against the policy
        success, err := evaluatePolicy(policy, repoInfo)
        if err != nil {
            log.Printf("Policy evaluation error for %s: %v", repoInfo.FullName, err)
            if strings.Contains(err.Error(), "rego_parse_error") {
                repoInfo.ScanResult = "Rego Parsing Error"
            } else {
                repoInfo.ScanResult = err.Error() // General error
            }
        } else if success {
            repoInfo.ScanResult = "Success"
        } else {
            repoInfo.ScanResult = "Failure"
        }

        scannedRepos = append(scannedRepos, repoInfo)
    }

    log.Println("Scan complete. Returning results.")
    return scannedRepos
}

// scanRepository fetches repo metadata and permissions
func scanRepository(ctx context.Context, org string, repo *github.Repository, client *github.Client) RepositoryInfo {
    repoDetails, _, err := client.Repositories.Get(ctx, org, repo.GetName())
    if err != nil {
        log.Printf("Skipping %s due to error: %v", repo.GetName(), err)
        return RepositoryInfo{}
    }

    // Fetch collaborator/team permissions
    permissions := FetchRepositoryPermissions(ctx, repoDetails, org, client)

    // Return normalized data
    return NormalizeRepoData(repoDetails, permissions)
}

// FetchRepositoryPermissions retrieves collaborator permissions for a repository
func FetchRepositoryPermissions(ctx context.Context, repo *github.Repository, org string, client *github.Client) []RepositoryPermissions {
    owner := repo.GetOwner().GetLogin()
    repoName := repo.GetName()

    collaborators, _, err := client.Repositories.ListCollaborators(ctx, owner, repoName, nil)
    if err != nil {
        log.Printf("Error fetching collaborators for %s: %v", repoName, err)
        return nil
    }

    teams, _, err := client.Repositories.ListTeams(ctx, owner, repoName, nil)
    if err != nil {
        log.Printf("Error fetching teams for %s: %v", repoName, err)
    }

    // Map team members to their respective teams
    teamMembers := make(map[string]string)
    for _, team := range teams {
        teamSlug := team.GetSlug()
        members, _, err := client.Teams.ListTeamMembersBySlug(ctx, org, teamSlug, nil)
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
        perm, _, err := client.Repositories.GetPermissionLevel(ctx, owner, repoName, collab.GetLogin())
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

// evaluatePolicy runs the repository data against the provided Rego policy
func evaluatePolicy(policy string, input interface{}) (bool, error) {
    ctx := context.Background()

    r := rego.New(
        rego.Query("data.repository"),
        rego.Module("repository.rego", policy),
        rego.Input(input),
    )

    query, err := r.PrepareForEval(ctx)
    if err != nil {
        return false, fmt.Errorf("failed to prepare rego query: %w", err)
    }

    rs, err := query.Eval(ctx)
    if err != nil {
        return false, fmt.Errorf("failed to evaluate policy: %w", err)
    }

    if len(rs) > 0 && len(rs[0].Expressions) > 0 {
        policyResults, ok := rs[0].Expressions[0].Value.(map[string]interface{})
        if !ok {
            return false, fmt.Errorf("invalid policy evaluation result format")
        }

        // Check for deny
        if deny, exists := policyResults["deny"].(bool); exists && deny {
            return false, nil
        }
        // Check for allow
        if allow, exists := policyResults["allow"].(bool); exists && allow {
            return true, nil
        }
    }
    // Default: deny if no explicit allow
    return false, nil
}

// NormalizeRepoData structures repository data
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