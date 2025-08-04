package pom

import (
	"strings"
	"sync"
)

var unresolvableRemoteRepoPathsMutex = &sync.Mutex{}
var unresolvableRemoteRepoPaths = make(map[string]bool)

var obsoleteRemoteRepoPaths = []string{
	"oss.sonatype.org",
}

func isObsoleteRepo(repo string) bool {
	for _, obsoleteRepo := range obsoleteRemoteRepoPaths {
		if strings.Contains(repo, obsoleteRepo) {
			return true
		}
	}
	return false
}

func isUnresolvableRemoteRepoPath(repo string) bool {
	unresolvableRemoteRepoPathsMutex.Lock()
	defer unresolvableRemoteRepoPathsMutex.Unlock()
	return unresolvableRemoteRepoPaths[repo]
}

func addUnresolvableRemoteRepoPath(repo string) {
	unresolvableRemoteRepoPathsMutex.Lock()
	defer unresolvableRemoteRepoPathsMutex.Unlock()
	unresolvableRemoteRepoPaths[repo] = true
}
