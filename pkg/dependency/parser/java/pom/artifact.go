package pom

import (
	"fmt"
	"strings"
	"sync"

	"github.com/samber/lo"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
	"github.com/aquasecurity/trivy/pkg/version/doc"
)

var (
	emptyVersionWarn = sync.OnceFunc(func() {
		log.WithPrefix("pom").Warn("Dependency version cannot be determined. Child dependencies will not be found.",
			// e.g. https://trivy.dev/latest/docs/coverage/language/java/#empty-dependency-version
			log.String("details", doc.URL("/docs/coverage/language/java/", "empty-dependency-version")))
	})
)

type artifact struct {
	GroupID    string
	ArtifactID string
	Version    version
	Licenses   []string

	// Scope is the effective dependency scope in the context of the dependency tree.
	// It is computed using Maven's scope transition matrix during BFS traversal.
	// See: https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#dependency-scope
	Scope string

	Exclusions set.Set[string]

	Module       bool
	Relationship ftypes.Relationship

	Locations ftypes.Locations
}

func newArtifact(groupID, artifactID, version string, licenses []string, props map[string]string) artifact {
	return artifact{
		GroupID:      evaluateVariable(groupID, props, nil),
		ArtifactID:   evaluateVariable(artifactID, props, nil),
		Version:      newVersion(evaluateVariable(version, props, nil)),
		Licenses:     licenses,
		Relationship: ftypes.RelationshipIndirect, // default
	}
}

func (a artifact) IsEmpty() bool {
	if a.GroupID == "" || a.ArtifactID == "" {
		return true
	}
	if a.Version.String() == "" {
		emptyVersionWarn()
		log.WithPrefix("pom").Debug("Dependency version cannot be determined.",
			log.String("GroupID", a.GroupID),
			log.String("ArtifactID", a.ArtifactID),
		)
	}
	return false
}

func (a artifact) Equal(o artifact) bool {
	return a.GroupID == o.GroupID || a.ArtifactID == o.ArtifactID || a.Version.String() == o.Version.String()
}

func (a artifact) ToPOMLicenses() pomLicenses {
	return pomLicenses{
		License: lo.Map(a.Licenses, func(lic string, _ int) pomLicense {
			return pomLicense{Name: lic}
		}),
	}
}

func (a artifact) Inherit(parent artifact) artifact {
	// inherited from a parent
	if a.GroupID == "" {
		a.GroupID = parent.GroupID
	}

	if len(a.Licenses) == 0 {
		a.Licenses = parent.Licenses
	}

	if a.Version.String() == "" {
		a.Version = parent.Version
	}
	return a
}

func (a artifact) Name() string {
	return fmt.Sprintf("%s:%s", a.GroupID, a.ArtifactID)
}

func (a artifact) String() string {
	return fmt.Sprintf("%s:%s", a.Name(), a.Version)
}

type version struct {
	ver  string
	hard bool
}

// newVersion parses a Maven version string, handling:
//   - Soft requirements: "1.0" (can be overridden by dependency mediation)
//   - Hard requirements: "[1.0]" (exact version, cannot be overridden)
//   - Version ranges: "[1.0,2.0)", "(,1.0]", "[1.0,)", etc.
//
// For version ranges, the best usable version is extracted:
//   - Lower bound is preferred when available (e.g., "[1.0,2.0)" → "1.0")
//   - Upper bound is used when no lower bound exists (e.g., "(,2.0]" → "2.0")
//
// See: https://maven.apache.org/enforcer/enforcer-rules/versionRanges.html
func newVersion(s string) version {
	s = strings.TrimSpace(s)
	if s == "" {
		return version{}
	}

	// Hard requirement: exactly "[x.y.z]" with no comma
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") && !strings.Contains(s, ",") {
		return version{
			ver:  strings.Trim(s, "[]"),
			hard: true,
		}
	}

	// Version range: contains range delimiters
	if strings.ContainsAny(s, ",()[]") {
		resolved := resolveVersionRange(s)
		return version{
			ver:  resolved,
			hard: resolved != "",
		}
	}

	// Soft requirement: plain version string
	return version{
		ver: s,
	}
}

// versionRange represents a single Maven version range like [1.0,2.0) or (,1.0].
type versionRange struct {
	min          string
	minInclusive bool
	max          string
	maxInclusive bool
}

// resolveVersionRange parses a Maven version range specification and returns
// the best usable version. Since Trivy performs offline analysis (without querying
// repository metadata for all available versions), we use a heuristic:
//   - For ranges with a lower bound: use the lower bound (conservative estimate)
//   - For ranges with only an upper bound: use the upper bound
//   - For multiple ranges: use the first range that yields a version
//
// Examples:
//
//	"[1.0,2.0)" → "1.0"
//	"(,1.5]"    → "1.5"
//	"[1.0,)"    → "1.0"
//	"(,1.0],[1.2,)" → "1.2"  (first non-empty lower bound)
func resolveVersionRange(s string) string {
	ranges := parseVersionRanges(s)
	if len(ranges) == 0 {
		return ""
	}

	// Try to find a range with a lower bound first (preferred)
	for _, r := range ranges {
		if r.min != "" {
			return r.min
		}
	}

	// Fall back to the upper bound of the first range
	for _, r := range ranges {
		if r.max != "" {
			return r.max
		}
	}

	return ""
}

// parseVersionRanges splits a Maven version range specification into individual ranges.
// Supports multi-range specifications like "(,1.0],[1.2,)".
func parseVersionRanges(s string) []versionRange {
	var ranges []versionRange

	// Split multi-range specs by tracking bracket depth.
	// Each range is enclosed in [] or () delimiters.
	depth := 0
	start := 0
	for i, c := range s {
		switch c {
		case '[', '(':
			if depth == 0 {
				start = i
			}
			depth++
		case ']', ')':
			depth--
			if depth == 0 {
				if r, ok := parseSingleRange(s[start : i+1]); ok {
					ranges = append(ranges, r)
				}
			}
		}
	}
	return ranges
}

// parseSingleRange parses a single version range like "[1.0,2.0)" or "(,1.0]".
func parseSingleRange(s string) (versionRange, bool) {
	if len(s) < 2 {
		return versionRange{}, false
	}

	r := versionRange{
		minInclusive: s[0] == '[',
		maxInclusive: s[len(s)-1] == ']',
	}

	inner := s[1 : len(s)-1]
	parts := strings.SplitN(inner, ",", 2)

	if len(parts) == 1 {
		// Exact version: [1.0]
		v := strings.TrimSpace(parts[0])
		r.min = v
		r.max = v
		return r, v != ""
	}

	r.min = strings.TrimSpace(parts[0])
	r.max = strings.TrimSpace(parts[1])

	if r.min == "" && r.max == "" {
		return versionRange{}, false
	}

	return r, true
}

// shouldOverride determines if the existing version (v1) should be replaced by a new version (v2).
// In Maven, hard version requirements (specified with brackets like [1.0]) always take precedence
// over soft requirements. This mirrors Maven's behavior where dependencyManagement and explicit
// version declarations override transitive dependency mediation.
func (v1 version) shouldOverride(v2 version) bool {
	if !v1.hard && v2.hard {
		return true
	}
	return false
}

func (v1 version) String() string {
	return v1.ver
}

// effectiveScope computes the effective scope of a transitive dependency using Maven's
// scope transition matrix. The effective scope depends on the parent dependency's scope
// and the transitive dependency's declared scope.
//
// Maven scope transition matrix:
//
//	         | compile  | provided | runtime  | test
//	---------|----------|----------|----------|------
//	compile  | compile  | -        | runtime  | -
//	provided | provided | -        | provided | -
//	runtime  | runtime  | -        | runtime  | -
//	test     | test     | -        | test     | -
//
// An empty return value means the dependency should be excluded.
//
// See: https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#dependency-scope
func effectiveScope(parentScope, depScope string) string {
	// Default scope is "compile"
	if parentScope == "" {
		parentScope = "compile"
	}
	if depScope == "" {
		depScope = "compile"
	}

	// "provided" and "test" scoped transitive dependencies are always excluded
	if depScope == "provided" || depScope == "test" {
		return ""
	}

	// "system" scope is treated like "provided" for transitivity
	if depScope == "system" {
		return ""
	}

	switch parentScope {
	case "compile":
		// compile + compile = compile
		// compile + runtime = runtime
		if depScope == "runtime" {
			return "runtime"
		}
		return "compile"
	case "provided":
		// provided + compile = provided
		// provided + runtime = provided
		return "provided"
	case "runtime":
		// runtime + compile = runtime
		// runtime + runtime = runtime
		return "runtime"
	case "test":
		// test + compile = test
		// test + runtime = test
		return "test"
	}

	return depScope
}
