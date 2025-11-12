package tree

import (
	"bytes"
	"strings"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestPrinter_PrintDependencyTree(t *testing.T) {
	tests := []struct {
		name     string
		packages []ftypes.Package
		target   string
		opts     PrintOptions
		want     []string // strings that should be present in output
	}{
		{
			name: "simple tree with root and direct dependencies",
			packages: []ftypes.Package{
				{
					ID:           "root@1.0.0",
					Name:         "root",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
					DependsOn:    []string{"dep1@1.0.0", "dep2@2.0.0"},
				},
				{
					ID:           "dep1@1.0.0",
					Name:         "dep1",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipDirect,
					DependsOn:    []string{"dep3@3.0.0"},
				},
				{
					ID:           "dep2@2.0.0",
					Name:         "dep2",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "dep3@3.0.0",
					Name:         "dep3",
					Version:      "3.0.0",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			target: "test-project",
			opts: PrintOptions{
				Format:            "tree",
				ShowAll:           false,
				ShowRelationships: true,
			},
			want: []string{
				"Dependency Tree",
				"test-project",
				"root@1.0.0",
				"dep1@1.0.0",
				"dep2@2.0.0",
			},
		},
		{
			name: "list format",
			packages: []ftypes.Package{
				{
					ID:           "root@1.0.0",
					Name:         "root",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
					DependsOn:    []string{"dep1@1.0.0"},
				},
				{
					ID:           "dep1@1.0.0",
					Name:         "dep1",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipDirect,
					Dev:          true,
				},
			},
			target: "test-project",
			opts: PrintOptions{
				Format:            "list",
				ShowRelationships: true,
			},
			want: []string{
				"Dependency List",
				"test-project",
				"Root Dependencies",
				"Direct Dependencies",
				"root@1.0.0",
				"dep1@1.0.0",
				"[dev]",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			printer := NewPrinter(&buf, tt.opts)
			
			err := printer.PrintDependencyTree(tt.packages, tt.target)
			if err != nil {
				t.Errorf("PrintDependencyTree() error = %v", err)
				return
			}
			
			output := buf.String()
			for _, want := range tt.want {
				if !strings.Contains(output, want) {
					t.Errorf("PrintDependencyTree() output missing %q, got:\n%s", want, output)
				}
			}
		})
	}
}

func TestPrinter_PrintDependencyStats(t *testing.T) {
	packages := []ftypes.Package{
		{
			ID:           "root@1.0.0",
			Name:         "root",
			Version:      "1.0.0",
			Relationship: ftypes.RelationshipRoot,
			DependsOn:    []string{"dep1@1.0.0", "dep2@2.0.0"},
		},
		{
			ID:           "dep1@1.0.0",
			Name:         "dep1",
			Version:      "1.0.0",
			Relationship: ftypes.RelationshipDirect,
			Dev:          true,
		},
		{
			ID:           "dep2@2.0.0",
			Name:         "dep2",
			Version:      "2.0.0",
			Relationship: ftypes.RelationshipIndirect,
		},
	}

	var buf bytes.Buffer
	printer := NewPrinter(&buf, PrintOptions{})
	
	err := printer.PrintDependencyStats(packages, "test-project")
	if err != nil {
		t.Errorf("PrintDependencyStats() error = %v", err)
		return
	}
	
	output := buf.String()
	expectedStrings := []string{
		"Dependency Statistics",
		"test-project",
		"Total Packages: 3",
		"Development Dependencies: 1",
		"Root: 1",
		"Direct: 1",
		"Indirect: 1",
	}
	
	for _, want := range expectedStrings {
		if !strings.Contains(output, want) {
			t.Errorf("PrintDependencyStats() output missing %q, got:\n%s", want, output)
		}
	}
}

func TestPrinter_EmptyPackages(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinter(&buf, PrintOptions{Format: "tree"})
	
	err := printer.PrintDependencyTree([]ftypes.Package{}, "test-project")
	if err != nil {
		t.Errorf("PrintDependencyTree() error = %v", err)
		return
	}
	
	output := buf.String()
	if !strings.Contains(output, "No packages found") {
		t.Errorf("PrintDependencyTree() should handle empty packages, got: %s", output)
	}
}

func TestFindRootPackages(t *testing.T) {
	packages := []ftypes.Package{
		{
			ID:           "root@1.0.0",
			Name:         "root",
			Version:      "1.0.0",
			Relationship: ftypes.RelationshipRoot,
		},
		{
			ID:           "direct@1.0.0",
			Name:         "direct",
			Version:      "1.0.0",
			Relationship: ftypes.RelationshipDirect,
		},
		{
			ID:           "indirect@1.0.0",
			Name:         "indirect",
			Version:      "1.0.0",
			Relationship: ftypes.RelationshipIndirect,
		},
	}

	printer := &Printer{opts: PrintOptions{ShowAll: false}}
	roots := printer.findRootPackages(packages)
	
	if len(roots) != 2 {
		t.Errorf("findRootPackages() should return 2 root packages, got %d", len(roots))
	}
	
	// Check that root and direct packages are included
	foundRoot := false
	foundDirect := false
	for _, pkg := range roots {
		if pkg.Name == "root" {
			foundRoot = true
		}
		if pkg.Name == "direct" {
			foundDirect = true
		}
	}
	
	if !foundRoot {
		t.Error("findRootPackages() should include root package")
	}
	if !foundDirect {
		t.Error("findRootPackages() should include direct package")
	}
}
