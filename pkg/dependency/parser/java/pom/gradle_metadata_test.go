package pom

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGradleModuleMetadata(t *testing.T) {
	tests := []struct {
		name        string
		jsonContent string
		wantErr     bool
		validate    func(t *testing.T, meta *gradleModuleMetadata)
	}{
		{
			name: "valid metadata with version ranges",
			jsonContent: `{
				"formatVersion": "1.1",
				"component": {
					"group": "com.example.app",
					"module": "app-bom",
					"version": "1.5-SNAPSHOT"
				},
				"variants": [
					{
						"name": "apiElements",
						"attributes": {
							"org.gradle.category": "platform",
							"org.gradle.usage": "java-api",
							"org.gradle.jvm.version": 17
						},
						"dependencyConstraints": [
							{
								"group": "com.example.services",
								"module": "service-api",
								"version": {
									"strictly": "[1.4-SNAPSHOT, 1.5-SNAPSHOT]",
									"requires": "[1.4-SNAPSHOT, 1.5-SNAPSHOT]",
									"prefers": "1.5-SNAPSHOT"
								}
							},
							{
								"group": "com.example.services",
								"module": "service-core",
								"version": {
									"strictly": "[1.5-SNAPSHOT, 1.6)",
									"requires": "[1.5-SNAPSHOT, 1.6)",
									"prefers": "1.5-SNAPSHOT"
								}
							}
						]
					}
				]
			}`,
			wantErr: false,
			validate: func(t *testing.T, meta *gradleModuleMetadata) {
				assert.Equal(t, "1.1", meta.FormatVersion)
				assert.Equal(t, "com.example.app", meta.Component.Group)
				assert.Equal(t, "app-bom", meta.Component.Module)
				assert.Equal(t, "1.5-SNAPSHOT", meta.Component.Version)
				assert.Len(t, meta.Variants, 1)
				assert.Len(t, meta.Variants[0].DependencyConstraints, 2)
				
				// Verify attributes can contain mixed types
				assert.Equal(t, "platform", meta.Variants[0].Attributes["org.gradle.category"])
				assert.Equal(t, float64(17), meta.Variants[0].Attributes["org.gradle.jvm.version"])
				
				// Check first constraint
				constraint1 := meta.Variants[0].DependencyConstraints[0]
				assert.Equal(t, "com.example.services", constraint1.Group)
				assert.Equal(t, "service-api", constraint1.Module)
				assert.Equal(t, "1.5-SNAPSHOT", constraint1.Version.Prefers)
				assert.Equal(t, "[1.4-SNAPSHOT, 1.5-SNAPSHOT]", constraint1.Version.Requires)
				
				// Check second constraint
				constraint2 := meta.Variants[0].DependencyConstraints[1]
				assert.Equal(t, "com.example.services", constraint2.Group)
				assert.Equal(t, "service-core", constraint2.Module)
				assert.Equal(t, "1.5-SNAPSHOT", constraint2.Version.Prefers)
			},
		},
		{
			name: "metadata with dependencies (not constraints)",
			jsonContent: `{
				"formatVersion": "1.1",
				"component": {
					"group": "com.example",
					"module": "example-lib",
					"version": "1.0.0"
				},
				"variants": [
					{
						"name": "apiElements",
						"attributes": {},
						"dependencies": [
							{
								"group": "org.springframework",
								"module": "spring-core",
								"version": {
									"requires": "5.3.0",
									"prefers": "5.3.10"
								}
							}
						]
					}
				]
			}`,
			wantErr: false,
			validate: func(t *testing.T, meta *gradleModuleMetadata) {
				assert.Len(t, meta.Variants, 1)
				assert.Len(t, meta.Variants[0].Dependencies, 1)
				
				dep := meta.Variants[0].Dependencies[0]
				assert.Equal(t, "org.springframework", dep.Group)
				assert.Equal(t, "spring-core", dep.Module)
				assert.Equal(t, "5.3.10", dep.Version.Prefers)
			},
		},
		{
			name:        "invalid JSON",
			jsonContent: `{invalid json}`,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.jsonContent)
			meta, err := parseGradleModuleMetadata(reader)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, meta)
			
			if tt.validate != nil {
				tt.validate(t, meta)
			}
		})
	}
}

func TestGradleModuleMetadata_GetPreferredVersion(t *testing.T) {
	tests := []struct {
		name          string
		metadata      *gradleModuleMetadata
		groupID       string
		artifactID    string
		wantVersion   string
	}{
		{
			name: "find preferred version in dependencyConstraints",
			metadata: &gradleModuleMetadata{
				Variants: []gradleModuleVariant{
					{
						DependencyConstraints: []gradleModuleDependencyConstraint{
							{
								Group:  "com.example.services",
								Module: "service-api",
								Version: gradleModuleVersionSpec{
									Strictly: "[1.4-SNAPSHOT, 1.5-SNAPSHOT]",
									Requires: "[1.4-SNAPSHOT, 1.5-SNAPSHOT]",
									Prefers:  "1.5-SNAPSHOT",
								},
							},
						},
					},
				},
			},
			groupID:     "com.example.services",
			artifactID:  "service-api",
			wantVersion: "1.5-SNAPSHOT",
		},
		{
			name: "find preferred version in dependencies",
			metadata: &gradleModuleMetadata{
				Variants: []gradleModuleVariant{
					{
						Dependencies: []gradleModuleDependency{
							{
								Group:  "org.springframework",
								Module: "spring-core",
								Version: gradleModuleVersionSpec{
									Requires: "5.3.0",
									Prefers:  "5.3.10",
								},
							},
						},
					},
				},
			},
			groupID:     "org.springframework",
			artifactID:  "spring-core",
			wantVersion: "5.3.10",
		},
		{
			name: "fallback to requires when no prefers",
			metadata: &gradleModuleMetadata{
				Variants: []gradleModuleVariant{
					{
						DependencyConstraints: []gradleModuleDependencyConstraint{
							{
								Group:  "com.example",
								Module: "example-lib",
								Version: gradleModuleVersionSpec{
									Requires: "2.0.0",
								},
							},
						},
					},
				},
			},
			groupID:     "com.example",
			artifactID:  "example-lib",
			wantVersion: "2.0.0",
		},
		{
			name: "not found returns empty string",
			metadata: &gradleModuleMetadata{
				Variants: []gradleModuleVariant{
					{
						DependencyConstraints: []gradleModuleDependencyConstraint{
							{
								Group:  "com.other",
								Module: "other-lib",
								Version: gradleModuleVersionSpec{
									Prefers: "1.0.0",
								},
							},
						},
					},
				},
			},
			groupID:     "com.notfound",
			artifactID:  "notfound-lib",
			wantVersion: "",
		},
		{
			name: "search multiple variants",
			metadata: &gradleModuleMetadata{
				Variants: []gradleModuleVariant{
					{
						Name: "apiElements",
						DependencyConstraints: []gradleModuleDependencyConstraint{
							{
								Group:  "com.example",
								Module: "lib-a",
								Version: gradleModuleVersionSpec{
									Prefers: "1.0.0",
								},
							},
						},
					},
					{
						Name: "runtimeElements",
						DependencyConstraints: []gradleModuleDependencyConstraint{
							{
								Group:  "com.example",
								Module: "lib-b",
								Version: gradleModuleVersionSpec{
									Prefers: "2.0.0",
								},
							},
						},
					},
				},
			},
			groupID:     "com.example",
			artifactID:  "lib-b",
			wantVersion: "2.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.metadata.getPreferredVersion(tt.groupID, tt.artifactID)
			assert.Equal(t, tt.wantVersion, got)
		})
	}
}

func TestHasGradleMetadataMarker(t *testing.T) {
	tests := []struct {
		name       string
		pomContent string
		want       bool
	}{
		{
			name: "has gradle metadata marker",
			pomContent: `<?xml version="1.0" encoding="UTF-8"?>
<!-- do_not_remove: published-with-gradle-metadata -->
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>example</artifactId>
  <version>1.0.0</version>
</project>`,
			want: true,
		},
		{
			name: "marker with different formatting",
			pomContent: `<?xml version="1.0" encoding="UTF-8"?>
<!--do_not_remove: published-with-gradle-metadata-->
<project>
</project>`,
			want: true,
		},
		{
			name: "no marker",
			pomContent: `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>example</artifactId>
  <version>1.0.0</version>
</project>`,
			want: false,
		},
		{
			name:       "empty content",
			pomContent: "",
			want:       false,
		},
		{
			name: "marker in different location",
			pomContent: `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <!-- do_not_remove: published-with-gradle-metadata -->
  <groupId>com.example</groupId>
</project>`,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasGradleMetadataMarker([]byte(tt.pomContent))
			assert.Equal(t, tt.want, got)
		})
	}
}
