package pom

import (
	"testing"
)

func TestIsGCPArtifactRegistry(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{
			name: "GCP Artifact Registry URL",
			url:  "https://us-central1-maven.pkg.dev/my-project/my-repo",
			want: true,
		},
		{
			name: "GCP Artifact Registry URL with region",
			url:  "https://europe-west1-maven.pkg.dev/my-project/my-repo",
			want: true,
		},
		{
			name: "GCS bucket URL",
			url:  "gcs://my-bucket/path",
			want: false,
		},
		{
			name: "Regular Maven Central",
			url:  "https://repo.maven.apache.org/maven2",
			want: false,
		},
		{
			name: "Storage googleapis URL",
			url:  "https://storage.googleapis.com/my-bucket",
			want: false,
		},
		{
			name: "Empty URL",
			url:  "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsGCPArtifactRegistry(tt.url); got != tt.want {
				t.Errorf("IsGCPArtifactRegistry(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestIsGCSBucket(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{
			name: "GCS bucket URL",
			url:  "gcs://my-bucket/path",
			want: true,
		},
		{
			name: "GCS bucket URL root",
			url:  "gcs://my-bucket",
			want: true,
		},
		{
			name: "HTTPS storage URL",
			url:  "https://storage.googleapis.com/my-bucket",
			want: false,
		},
		{
			name: "GCP Artifact Registry",
			url:  "https://us-central1-maven.pkg.dev/my-project/my-repo",
			want: false,
		},
		{
			name: "Regular Maven Central",
			url:  "https://repo.maven.apache.org/maven2",
			want: false,
		},
		{
			name: "Empty URL",
			url:  "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsGCSBucket(tt.url); got != tt.want {
				t.Errorf("IsGCSBucket(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestIsGCPRepository(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{
			name: "GCP Artifact Registry",
			url:  "https://us-central1-maven.pkg.dev/my-project/my-repo",
			want: true,
		},
		{
			name: "GCS bucket URL",
			url:  "gcs://my-bucket/path",
			want: true,
		},
		{
			name: "Converted GCS to HTTPS",
			url:  "https://storage.googleapis.com/my-bucket/snapshots",
			want: true,
		},
		{
			name: "Storage googleapis with path",
			url:  "https://storage.googleapis.com/repo.example.com/releases",
			want: true,
		},
		{
			name: "Regular Maven Central",
			url:  "https://repo.maven.apache.org/maven2",
			want: false,
		},
		{
			name: "JCenter",
			url:  "https://jcenter.bintray.com",
			want: false,
		},
		{
			name: "Empty URL",
			url:  "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsGCPRepository(tt.url); got != tt.want {
				t.Errorf("IsGCPRepository(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestConvertGCSToHTTPS(t *testing.T) {
	tests := []struct {
		name    string
		gcsURL  string
		want    string
		wantErr bool
	}{
		{
			name:    "GCS bucket with path",
			gcsURL:  "gcs://repo.example.com/snapshots",
			want:    "https://storage.googleapis.com/repo.example.com/snapshots",
			wantErr: false,
		},
		{
			name:    "GCS bucket root",
			gcsURL:  "gcs://my-bucket",
			want:    "https://storage.googleapis.com/my-bucket",
			wantErr: false,
		},
		{
			name:    "GCS bucket with deep path",
			gcsURL:  "gcs://repo.example.com/releases/com/example/artifact/1.0.0",
			want:    "https://storage.googleapis.com/repo.example.com/releases/com/example/artifact/1.0.0",
			wantErr: false,
		},
		{
			name:    "Already HTTPS URL - should return as-is",
			gcsURL:  "https://storage.googleapis.com/my-bucket",
			want:    "https://storage.googleapis.com/my-bucket",
			wantErr: false,
		},
		{
			name:    "Regular Maven URL - should return as-is",
			gcsURL:  "https://repo.maven.apache.org/maven2",
			want:    "https://repo.maven.apache.org/maven2",
			wantErr: false,
		},
		{
			name:    "Invalid GCS URL - empty path",
			gcsURL:  "gcs://",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertGCSToHTTPS(tt.gcsURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConvertGCSToHTTPS(%q) error = %v, wantErr %v", tt.gcsURL, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ConvertGCSToHTTPS(%q) = %q, want %q", tt.gcsURL, got, tt.want)
			}
		})
	}
}

func TestGetAuthorizationHeader_NoCredentials(t *testing.T) {
	// Unset the environment variable (t.Setenv automatically restores after test)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

	cachedToken = nil

	name, value, err := GetAuthorizationHeader()

	if err != nil {
		t.Errorf("GetAuthorizationHeader() error = %v, expected nil when GOOGLE_APPLICATION_CREDENTIALS is not set", err)
	}

	if name != "" {
		t.Errorf("GetAuthorizationHeader() name = %q, want empty string when credentials not set", name)
	}

	if value != "" {
		t.Errorf("GetAuthorizationHeader() value = %q, want empty string when credentials not set", value)
	}
}

func TestGetAuthorizationHeader_InvalidCredentialsFile(t *testing.T) {
	// Set to a non-existent file (t.Setenv automatically restores after test)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/nonexistent/path/to/credentials.json")

	cachedToken = nil

	name, value, err := GetAuthorizationHeader()

	if err == nil {
		t.Error("GetAuthorizationHeader() expected error for invalid credentials file, got nil")
	}

	if name != "" {
		t.Errorf("GetAuthorizationHeader() name = %q, want empty string when credentials file is invalid", name)
	}

	if value != "" {
		t.Errorf("GetAuthorizationHeader() value = %q, want empty string when credentials file is invalid", value)
	}
}
