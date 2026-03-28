package pom

import (
	"context"
	"fmt"
	"os"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	cloudPlatformScope     = "https://www.googleapis.com/auth/cloud-platform"
	authorizationHeaderKey = "Authorization"
)

// Global token cache - generated once and auto-refreshes when expired
var cachedToken *oauth2.Token

// IsGCPArtifactRegistry checks if URL is GCP Artifact Registry
func IsGCPArtifactRegistry(url string) bool {
	return strings.Contains(url, ".pkg.dev")
}

// IsGCSBucket checks if URL is a GCS bucket with gcs:// protocol
func IsGCSBucket(url string) bool {
	return strings.HasPrefix(url, "gcs://")
}

// IsGCPRepository checks if URL is any GCP-hosted repository (Artifact Registry, GCS bucket, or converted GCS HTTPS)
func IsGCPRepository(url string) bool {
	return IsGCPArtifactRegistry(url) || IsGCSBucket(url) || strings.Contains(url, "storage.googleapis.com")
}

// ConvertGCSToHTTPS converts gcs:// URLs to HTTPS format for HTTP requests
func ConvertGCSToHTTPS(gcsURL string) (string, error) {
	if !strings.HasPrefix(gcsURL, "gcs://") {
		return gcsURL, nil // Not a GCS URL, return as-is
	}

	// Remove gcs:// prefix
	path := strings.TrimPrefix(gcsURL, "gcs://")
	if path == "" {
		return "", fmt.Errorf("invalid GCS URL: %s", gcsURL)
	}

	// Convert to HTTPS URL
	httpsURL := fmt.Sprintf("https://storage.googleapis.com/%s", path)
	return httpsURL, nil
}

// GetAuthorizationHeader returns the Authorization header name and value for GCP repositories.
// The oauth2.Token is cached globally and auto-refreshes when expired.
// Returns empty strings if GOOGLE_APPLICATION_CREDENTIALS is not set or if token generation fails.
func GetAuthorizationHeader() (name, value string, err error) {
	logger := log.WithPrefix("gcp-auth")

	if cachedToken != nil && cachedToken.Valid() {
		headerValue := fmt.Sprintf("Bearer %s", cachedToken.AccessToken)
		return authorizationHeaderKey, headerValue, nil
	}

	// Check if GCP auth is enabled
	credPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if credPath == "" {
		return "", "", nil
	}

	logger.Debug("Generating GCP access token", log.String("credentials_file", credPath))

	// Read credentials file
	data, err := os.ReadFile(credPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read GCP credentials file: %w", err)
	}

	// Parse credentials and get token
	creds, err := google.CredentialsFromJSON(context.Background(), data, cloudPlatformScope)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse GCP credentials: %w", err)
	}

	token, err := creds.TokenSource.Token()
	if err != nil {
		return "", "", fmt.Errorf("failed to get GCP access token: %w", err)
	}

	cachedToken = token
	logger.Info("GCP access token generated successfully")

	return authorizationHeaderKey, fmt.Sprintf("Bearer %s", token.AccessToken), nil
}

// addGCPAuthToRepos adds GCP authentication headers to GCP repositories.
// GCS URLs (gcs://) are converted to HTTPS, and Authorization headers are added once.
// This is called during repository registration, not on every request.
func addGCPAuthToRepos(repos []RemoteRepositoryConfig) []RemoteRepositoryConfig {
	logger := log.WithPrefix("pom")

	result := make([]RemoteRepositoryConfig, 0, len(repos))
	for _, repo := range repos {
		newRepo := repo

		// Convert GCS URLs to HTTPS
		if IsGCSBucket(repo.URL) {
			httpsURL, err := ConvertGCSToHTTPS(repo.URL)
			if err != nil {
				logger.Debug("Failed to convert GCS URL", log.String("url", repo.URL), log.Err(err))
				result = append(result, repo)
				continue
			}
			newRepo.URL = httpsURL
		}

		// Add GCP authentication headers (after URL conversion if needed)
		if IsGCPRepository(newRepo.URL) {
			headerName, headerValue, err := GetAuthorizationHeader()
			if err != nil {
				logger.Debug("Failed to get GCP auth header", log.String("repo", newRepo.URL), log.Err(err))
				// Continue without auth - might still work for public repos
			} else if headerName != "" && headerValue != "" {
				newRepo.HTTPHeaders = append(newRepo.HTTPHeaders, struct {
					Name  string
					Value string
				}{
					Name:  headerName,
					Value: headerValue,
				})
				logger.Debug("Added GCP authentication to repository", log.String("repo", newRepo.URL))
			}
		}

		result = append(result, newRepo)
	}
	return result
}
