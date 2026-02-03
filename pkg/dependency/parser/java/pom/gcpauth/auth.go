package gcpauth

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
)

var (
	// Global token cache - generated once and auto-refreshes when expired
	cachedToken *oauth2.Token
	tokenMu     sync.RWMutex
)

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
// Example: gcs://repo.revolut.com/snapshots -> https://storage.googleapis.com/repo.revolut.com/snapshots
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
// Thread-safe - can be called concurrently from multiple goroutines.
// Returns empty strings if GOOGLE_APPLICATION_CREDENTIALS is not set or if token generation fails.
func GetAuthorizationHeader() (name, value string, err error) {
	logger := log.WithPrefix("gcp-auth")

	// Check if GCP auth is enabled
	credPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if credPath == "" {
		return "", "", nil
	}

	// Check if we have a valid cached token
	tokenMu.RLock()
	if cachedToken != nil && cachedToken.Valid() {
		headerValue := fmt.Sprintf("Bearer %s", cachedToken.AccessToken)
		tokenMu.RUnlock()
		return "Authorization", headerValue, nil
	}
	tokenMu.RUnlock()

	// Need to generate a new token
	tokenMu.Lock()
	defer tokenMu.Unlock()

	// Double-check after acquiring write lock (another goroutine might have generated it)
	if cachedToken != nil && cachedToken.Valid() {
		return "Authorization", fmt.Sprintf("Bearer %s", cachedToken.AccessToken), nil
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

	return "Authorization", fmt.Sprintf("Bearer %s", token.AccessToken), nil
}
