package pom

import (
	"encoding/json"
	"io"

	"golang.org/x/xerrors"
)

// Gradle Module Metadata structures
// Reference: https://github.com/gradle/gradle/blob/master/subprojects/docs/src/docs/design/gradle-module-metadata-latest-specification.md

type gradleModuleMetadata struct {
	FormatVersion string                `json:"formatVersion"`
	Component     gradleModuleComponent `json:"component"`
	Variants      []gradleModuleVariant `json:"variants"`
}

type gradleModuleComponent struct {
	Group   string `json:"group"`
	Module  string `json:"module"`
	Version string `json:"version"`
}

type gradleModuleVariant struct {
	Name                  string                             `json:"name"`
	Attributes            map[string]interface{}             `json:"attributes"` // Can be string, number, bool
	Dependencies          []gradleModuleDependency           `json:"dependencies,omitempty"`
	DependencyConstraints []gradleModuleDependencyConstraint `json:"dependencyConstraints,omitempty"`
}

type gradleModuleDependency struct {
	Group   string                  `json:"group"`
	Module  string                  `json:"module"`
	Version gradleModuleVersionSpec `json:"version,omitempty"`
}

type gradleModuleDependencyConstraint struct {
	Group   string                  `json:"group"`
	Module  string                  `json:"module"`
	Version gradleModuleVersionSpec `json:"version,omitempty"`
}

type gradleModuleVersionSpec struct {
	Strictly string `json:"strictly,omitempty"` // Hard requirement
	Requires string `json:"requires,omitempty"` // Minimum version or range
	Prefers  string `json:"prefers,omitempty"`  // Preferred version
}

// parseGradleModuleMetadata parses a Gradle Module Metadata JSON file
func parseGradleModuleMetadata(r io.Reader) (*gradleModuleMetadata, error) {
	var metadata gradleModuleMetadata
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&metadata); err != nil {
		return nil, xerrors.Errorf("failed to decode Gradle module metadata: %w", err)
	}
	return &metadata, nil
}

// getPreferredVersion extracts the preferred version for a given dependency
// from the Gradle Module Metadata. Returns empty string if not found.
func (m *gradleModuleMetadata) getPreferredVersion(groupID, artifactID string) string {
	for _, variant := range m.Variants {
		// Check dependencyConstraints (used in BOMs/platforms)
		for _, constraint := range variant.DependencyConstraints {
			if constraint.Group == groupID && constraint.Module == artifactID {
				// Prefer the "prefers" field if available
				if constraint.Version.Prefers != "" {
					return constraint.Version.Prefers
				}
				// Fall back to "requires" if no "prefers"
				if constraint.Version.Requires != "" {
					return constraint.Version.Requires
				}
			}
		}

		// Check dependencies (used in regular modules)
		for _, dep := range variant.Dependencies {
			if dep.Group == groupID && dep.Module == artifactID {
				if dep.Version.Prefers != "" {
					return dep.Version.Prefers
				}
				if dep.Version.Requires != "" {
					return dep.Version.Requires
				}
			}
		}
	}
	return ""
}

// hasGradleMetadataMarker checks if a POM has the Gradle metadata marker comment.
// This is a STANDARD marker added by Gradle's publishing plugins when publishing to Maven repositories.
// When present, it indicates that a richer Gradle Module Metadata (.module file) is available
// alongside the POM file, and should be preferred for dependency resolution.
//
// Reference: https://docs.gradle.org/current/userguide/publishing_gradle_module_metadata.html
// The marker format is: <!-- do_not_remove: published-with-gradle-metadata -->
func hasGradleMetadataMarker(pomContent []byte) bool {
	// Look for the marker: <!-- do_not_remove: published-with-gradle-metadata -->
	marker := []byte("published-with-gradle-metadata")
	return len(pomContent) > 0 && containsBytes(pomContent, marker)
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return false
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if matchBytes(haystack[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

func matchBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
