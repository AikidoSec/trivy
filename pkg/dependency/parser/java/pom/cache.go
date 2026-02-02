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

// getByName returns the first cached result matching the artifact name (groupId:artifactId),
// regardless of version. This is used for artifact relocation to find if the relocated
// artifact has already been resolved with a different version.
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
