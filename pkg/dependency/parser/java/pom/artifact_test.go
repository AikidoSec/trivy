package pom

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantVer  string
		wantHard bool
	}{
		{
			name:    "plain version (soft requirement)",
			input:   "1.0.0",
			wantVer: "1.0.0",
		},
		{
			name:     "exact hard version [1.0]",
			input:    "[1.0]",
			wantVer:  "1.0",
			wantHard: true,
		},
		{
			name:     "range with lower bound [1.5,2.0)",
			input:    "[1.5,2.0)",
			wantVer:  "1.5",
			wantHard: true,
		},
		{
			name:     "range with only upper bound (,3.0]",
			input:    "(,3.0]",
			wantVer:  "3.0",
			wantHard: true,
		},
		{
			name:     "range open-ended [2.0,)",
			input:    "[2.0,)",
			wantVer:  "2.0",
			wantHard: true,
		},
		{
			name:     "range both bounds [1.0,2.0]",
			input:    "[1.0,2.0]",
			wantVer:  "1.0",
			wantHard: true,
		},
		{
			name:     "multi-range (,1.0],[1.2,) picks first lower bound",
			input:    "(,1.0],[1.2,)",
			wantVer:  "1.2",
			wantHard: true,
		},
		{
			name:     "exclusion range (,1.1),(1.1,)",
			input:    "(,1.1),(1.1,)",
			wantVer:  "1.1",
			wantHard: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantVer: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newVersion(tt.input)
			assert.Equal(t, tt.wantVer, got.String())
			assert.Equal(t, tt.wantHard, got.hard)
		})
	}
}

func Test_resolveVersionRange(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "lower and upper bound",
			input: "[1.5,2.0)",
			want:  "1.5",
		},
		{
			name:  "only upper bound",
			input: "(,3.0]",
			want:  "3.0",
		},
		{
			name:  "only lower bound",
			input: "[2.0,)",
			want:  "2.0",
		},
		{
			name:  "exclusive lower bound",
			input: "(1.0,2.0)",
			want:  "1.0",
		},
		{
			name:  "multi-range prefers lower bound",
			input: "(,1.0],[1.2,)",
			want:  "1.2",
		},
		{
			name:  "empty range",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveVersionRange(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_parseVersionRanges(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []versionRange
	}{
		{
			name:  "single range with both bounds",
			input: "[1.0,2.0)",
			want: []versionRange{
				{min: "1.0", max: "2.0", minInclusive: true, maxInclusive: false},
			},
		},
		{
			name:  "only upper bound",
			input: "(,1.0]",
			want: []versionRange{
				{min: "", max: "1.0", minInclusive: false, maxInclusive: true},
			},
		},
		{
			name:  "multiple ranges",
			input: "(,1.0],[1.2,)",
			want: []versionRange{
				{min: "", max: "1.0", minInclusive: false, maxInclusive: true},
				{min: "1.2", max: "", minInclusive: true, maxInclusive: false},
			},
		},
		{
			name:  "exact version (shorthand)",
			input: "[1.5]",
			want: []versionRange{
				{min: "1.5", max: "1.5", minInclusive: true, maxInclusive: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseVersionRanges(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}

func Test_effectiveScope(t *testing.T) {
	// Test Maven's scope transition matrix
	// See: https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#dependency-scope
	tests := []struct {
		name        string
		parentScope string
		depScope    string
		want        string
	}{
		// compile parent row
		{name: "compile+compile=compile", parentScope: "compile", depScope: "compile", want: "compile"},
		{name: "compile+runtime=runtime", parentScope: "compile", depScope: "runtime", want: "runtime"},
		{name: "compile+provided=excluded", parentScope: "compile", depScope: "provided", want: ""},
		{name: "compile+test=excluded", parentScope: "compile", depScope: "test", want: ""},

		// provided parent row
		{name: "provided+compile=provided", parentScope: "provided", depScope: "compile", want: "provided"},
		{name: "provided+runtime=provided", parentScope: "provided", depScope: "runtime", want: "provided"},
		{name: "provided+provided=excluded", parentScope: "provided", depScope: "provided", want: ""},
		{name: "provided+test=excluded", parentScope: "provided", depScope: "test", want: ""},

		// runtime parent row
		{name: "runtime+compile=runtime", parentScope: "runtime", depScope: "compile", want: "runtime"},
		{name: "runtime+runtime=runtime", parentScope: "runtime", depScope: "runtime", want: "runtime"},
		{name: "runtime+provided=excluded", parentScope: "runtime", depScope: "provided", want: ""},
		{name: "runtime+test=excluded", parentScope: "runtime", depScope: "test", want: ""},

		// test parent row
		{name: "test+compile=test", parentScope: "test", depScope: "compile", want: "test"},
		{name: "test+runtime=test", parentScope: "test", depScope: "runtime", want: "test"},
		{name: "test+provided=excluded", parentScope: "test", depScope: "provided", want: ""},
		{name: "test+test=excluded", parentScope: "test", depScope: "test", want: ""},

		// default scopes (empty = compile)
		{name: "empty+empty=compile", parentScope: "", depScope: "", want: "compile"},
		{name: "empty+runtime=runtime", parentScope: "", depScope: "runtime", want: "runtime"},

		// system scope treated like provided for transitivity
		{name: "compile+system=excluded", parentScope: "compile", depScope: "system", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := effectiveScope(tt.parentScope, tt.depScope)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_shouldOverride(t *testing.T) {
	tests := []struct {
		name     string
		existing version
		incoming version
		want     bool
	}{
		{
			name:     "soft existing, hard incoming → override",
			existing: version{ver: "1.0", hard: false},
			incoming: version{ver: "2.0", hard: true},
			want:     true,
		},
		{
			name:     "hard existing, soft incoming → no override",
			existing: version{ver: "1.0", hard: true},
			incoming: version{ver: "2.0", hard: false},
			want:     false,
		},
		{
			name:     "soft existing, soft incoming → no override (nearest wins)",
			existing: version{ver: "1.0", hard: false},
			incoming: version{ver: "2.0", hard: false},
			want:     false,
		},
		{
			name:     "hard existing, hard incoming → no override (first hard wins)",
			existing: version{ver: "1.0", hard: true},
			incoming: version{ver: "2.0", hard: true},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.existing.shouldOverride(tt.incoming)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_evaluateVariable(t *testing.T) {
	type args struct {
		s     string
		props map[string]string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "happy path",
			args: args{
				s: "${java.version}",
				props: map[string]string{
					"java.version": "1.7",
				},
			},
			want: "1.7",
		},
		{
			name: "two variables",
			args: args{
				s: "${foo.name}-${bar.name}",
				props: map[string]string{
					"foo.name": "aaa",
					"bar.name": "bbb",
				},
			},
			want: "aaa-bbb",
		},
		{
			name: "looped variables",
			args: args{
				s: "${foo.name}",
				props: map[string]string{
					"foo.name": "${bar.name}",
					"bar.name": "${foo.name}",
				},
			},
			want: "",
		},
		{
			name: "same variables",
			args: args{
				s: "${foo.name}-${foo.name}",
				props: map[string]string{
					"foo.name": "aaa",
				},
			},
			want: "aaa-aaa",
		},
		{
			name: "nested variables",
			args: args{
				s: "${jackson.version.core}",
				props: map[string]string{
					"jackson.version":      "2.12.1",
					"jackson.version.core": "${jackson.version}",
				},
			},
			want: "2.12.1",
		},
		{
			name: "environmental variable",
			args: args{
				s: "${env.TEST_GO_DEP_PARSER}",
			},
			want: "1.2.3",
		},
		{
			name: "no variable",
			args: args{
				s: "1.12",
			},
			want: "1.12",
		},
	}

	envName := "TEST_GO_DEP_PARSER"
	t.Setenv(envName, "1.2.3")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateVariable(tt.args.s, tt.args.props, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
