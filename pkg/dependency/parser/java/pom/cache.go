package pom

import "fmt"

type pomCache map[string]*analysisResult

func newPOMCache() pomCache {
	return pomCache{}
}

func (c pomCache) put(art artifact, result analysisResult) {
	c[c.key(art)] = &result
}

func (c pomCache) get(art artifact) *analysisResult {
	return c[c.key(art)]
}

// getByName finds any cached result for an artifact with the given name (groupId:artifactId),
// regardless of version. Used for artifact relocation to check if the relocated artifact
// is already cached. Returns nil if not found.
func (c pomCache) getByName(name string) *analysisResult {
	for _, result := range c {
		if result != nil && result.artifact.Name() == name {
			return result
		}
	}
	return nil
}

func (c pomCache) key(art artifact) string {
	return fmt.Sprintf("%s:%s", art.Name(), art.Version)
}
