package pom

import "sync"

var unresolvableRemoteReposMutex = &sync.Mutex{}
var unresolvableRemoteRepos = make(map[string]bool)

func isUnresolvableRemoteRepo(repo string) bool {
	unresolvableRemoteReposMutex.Lock()
	defer unresolvableRemoteReposMutex.Unlock()
	return unresolvableRemoteRepos[repo]
}

func addUnresolvableRemoteRepo(repo string) {
	unresolvableRemoteReposMutex.Lock()
	defer unresolvableRemoteReposMutex.Unlock()
	unresolvableRemoteRepos[repo] = true
}
