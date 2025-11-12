package tree

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/xlab/treeprint"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/set"
)

// PrintOptions contains options for printing dependency trees
type PrintOptions struct {
	// ShowAll determines whether to show all packages or only root/direct dependencies
	ShowAll bool
	// MaxDepth limits the depth of the tree (0 = unlimited)
	MaxDepth int
	// ShowRelationships determines whether to show relationship types
	ShowRelationships bool
	// Format determines the output format (tree, list, etc.)
	Format string
}

// Printer handles dependency tree printing
type Printer struct {
	writer io.Writer
	opts   PrintOptions
}

// NewPrinter creates a new dependency tree printer
func NewPrinter(w io.Writer, opts PrintOptions) *Printer {
	return &Printer{
		writer: w,
		opts:   opts,
	}
}

// PrintDependencyTree prints the dependency tree for the given packages
func (p *Printer) PrintDependencyTree(packages []ftypes.Package, target string) error {
	if len(packages) == 0 {
		fmt.Fprintf(p.writer, "No packages found for %s\n", target)
		return nil
	}

	switch p.opts.Format {
	case "list":
		return p.printList(packages, target)
	case "tree":
		fallthrough
	default:
		return p.printTree(packages, target)
	}
}

// printTree prints packages in a tree format
func (p *Printer) printTree(packages []ftypes.Package, target string) error {
	// Build dependency maps
	pkgMap := make(map[string]ftypes.Package)
	childrenMap := make(map[string][]string)
	
	for _, pkg := range packages {
		pkgMap[pkg.ID] = pkg
		for _, dep := range pkg.DependsOn {
			childrenMap[pkg.ID] = append(childrenMap[pkg.ID], dep)
		}
	}

	// Sort children for consistent output
	for id := range childrenMap {
		sort.Strings(childrenMap[id])
	}

	// Find root packages (packages with no parents or marked as root/direct)
	rootPkgs := p.findRootPackages(packages)
	
	if len(rootPkgs) == 0 {
		fmt.Fprintf(p.writer, "No root packages found for %s\n", target)
		return nil
	}

	// Create tree structure
	root := treeprint.NewWithRoot(fmt.Sprintf("Dependency Tree\n===============\n%s", target))
	
	visited := set.New[string]()
	for _, rootPkg := range rootPkgs {
		p.addPackageToTree(root, rootPkg, pkgMap, childrenMap, visited, 0)
	}

	fmt.Fprint(p.writer, root.String())
	return nil
}

// printList prints packages in a simple list format
func (p *Printer) printList(packages []ftypes.Package, target string) error {
	fmt.Fprintf(p.writer, "Dependency List for %s\n", target)
	fmt.Fprintf(p.writer, "======================\n\n")

	// Group packages by relationship
	byRelationship := make(map[ftypes.Relationship][]ftypes.Package)
	for _, pkg := range packages {
		byRelationship[pkg.Relationship] = append(byRelationship[pkg.Relationship], pkg)
	}

	// Sort relationships for consistent output
	relationships := []ftypes.Relationship{
		ftypes.RelationshipRoot,
		ftypes.RelationshipWorkspace,
		ftypes.RelationshipDirect,
		ftypes.RelationshipIndirect,
		ftypes.RelationshipUnknown,
	}

	for _, rel := range relationships {
		pkgs := byRelationship[rel]
		if len(pkgs) == 0 {
			continue
		}

		fmt.Fprintf(p.writer, "%s Dependencies (%d):\n", strings.Title(rel.String()), len(pkgs))
		
		// Sort packages by name
		sort.Slice(pkgs, func(i, j int) bool {
			return pkgs[i].Name < pkgs[j].Name
		})

		for _, pkg := range pkgs {
			fmt.Fprintf(p.writer, "  - %s", p.formatPackage(pkg))
			if len(pkg.DependsOn) > 0 {
				fmt.Fprintf(p.writer, " (depends on %d packages)", len(pkg.DependsOn))
			}
			fmt.Fprintf(p.writer, "\n")
		}
		fmt.Fprintf(p.writer, "\n")
	}

	return nil
}

// findRootPackages identifies root packages in the dependency graph
func (p *Printer) findRootPackages(packages []ftypes.Package) []ftypes.Package {
	var roots []ftypes.Package
	
	if p.opts.ShowAll {
		// When showing all, include packages that are not dependencies of others
		dependents := set.New[string]()
		for _, pkg := range packages {
			for _, dep := range pkg.DependsOn {
				dependents.Append(dep)
			}
		}
		
		for _, pkg := range packages {
			if !dependents.Contains(pkg.ID) || 
			   pkg.Relationship == ftypes.RelationshipRoot || 
			   pkg.Relationship == ftypes.RelationshipWorkspace {
				roots = append(roots, pkg)
			}
		}
	} else {
		// Only show root and direct dependencies
		for _, pkg := range packages {
			if pkg.Relationship == ftypes.RelationshipRoot || 
			   pkg.Relationship == ftypes.RelationshipDirect ||
			   pkg.Relationship == ftypes.RelationshipWorkspace {
				roots = append(roots, pkg)
			}
		}
	}
	
	// Sort roots by name for consistent output
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].Name < roots[j].Name
	})
	
	return roots
}

// addPackageToTree recursively adds a package and its dependencies to the tree
func (p *Printer) addPackageToTree(parent treeprint.Tree, pkg ftypes.Package, pkgMap map[string]ftypes.Package, 
	childrenMap map[string][]string, visited set.Set[string], depth int) {
	
	// Check depth limit
	if p.opts.MaxDepth > 0 && depth >= p.opts.MaxDepth {
		return
	}
	
	// Avoid infinite loops
	if visited.Contains(pkg.ID) {
		parent.AddBranch(fmt.Sprintf("%s (circular dependency)", p.formatPackage(pkg)))
		return
	}
	
	visited.Append(pkg.ID)
	defer visited.Remove(pkg.ID) // Remove after processing to allow the same package in different branches
	
	// Add current package
	branch := parent.AddBranch(p.formatPackage(pkg))
	
	// Add dependencies
	children := childrenMap[pkg.ID]
	for _, childID := range children {
		if childPkg, exists := pkgMap[childID]; exists {
			p.addPackageToTree(branch, childPkg, pkgMap, childrenMap, visited, depth+1)
		} else {
			// Package not found in the map, show as missing
			branch.AddBranch(fmt.Sprintf("%s (not found)", childID))
		}
	}
}

// formatPackage formats a package for display
func (p *Printer) formatPackage(pkg ftypes.Package) string {
	var parts []string
	
	// Basic package info
	if pkg.Version != "" {
		parts = append(parts, fmt.Sprintf("%s@%s", pkg.Name, pkg.Version))
	} else {
		parts = append(parts, pkg.Name)
	}
	
	// Add relationship info if requested
	if p.opts.ShowRelationships && pkg.Relationship != ftypes.RelationshipUnknown {
		parts = append(parts, fmt.Sprintf("[%s]", pkg.Relationship.String()))
	}
	
	// Add dev dependency marker
	if pkg.Dev {
		parts = append(parts, "[dev]")
	}
	
	return strings.Join(parts, " ")
}

// PrintDependencyStats prints statistics about the dependencies
func (p *Printer) PrintDependencyStats(packages []ftypes.Package, target string) error {
	fmt.Fprintf(p.writer, "Dependency Statistics for %s\n", target)
	fmt.Fprintf(p.writer, "=============================\n\n")
	
	// Count by relationship
	relationshipCounts := make(map[ftypes.Relationship]int)
	devCount := 0
	totalDeps := 0
	
	for _, pkg := range packages {
		relationshipCounts[pkg.Relationship]++
		if pkg.Dev {
			devCount++
		}
		totalDeps += len(pkg.DependsOn)
	}
	
	fmt.Fprintf(p.writer, "Total Packages: %d\n", len(packages))
	fmt.Fprintf(p.writer, "Total Dependencies: %d\n", totalDeps)
	fmt.Fprintf(p.writer, "Development Dependencies: %d\n", devCount)
	fmt.Fprintf(p.writer, "\nBy Relationship:\n")
	
	relationships := []ftypes.Relationship{
		ftypes.RelationshipRoot,
		ftypes.RelationshipWorkspace,
		ftypes.RelationshipDirect,
		ftypes.RelationshipIndirect,
		ftypes.RelationshipUnknown,
	}
	
	for _, rel := range relationships {
		if count := relationshipCounts[rel]; count > 0 {
			fmt.Fprintf(p.writer, "  %s: %d\n", strings.Title(rel.String()), count)
		}
	}
	
	fmt.Fprintf(p.writer, "\n")
	return nil
}
