package pom

import "sync"

var unresolvableRemoteRepoPathsMutex = &sync.Mutex{}
var unresolvableRemoteRepoPaths = make(map[string]bool)

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
