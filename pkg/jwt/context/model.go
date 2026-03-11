//revive:disable var-naming // TODO: fix package naming
package context

import (
	"sync"
	"time"

	jwtAuth "github.com/ribeirohugo/go_middlewares/pkg/jwt"
)

const (
	expiredTokenMessage = "token has expired"
	unauthorizedMessage = "unauthorized"
)

// JWT is a JWTMiddleware that holds authentication data and dependencies.
//
// adminRole is the maximum permission role, that allows everything by default.
// claimsKey is the authentication key used by claims.
// tokenSecret the secret key to verify the integrity and authenticity of the JWT
// tokenMaxAge is the max duration of a token, in nanoseconds.
// skipList is the list of endpoints that are ignored for JWT verification.
// permissionsMap is the list of endpoints, associated to the allowed permission roles.
// blacklist is an in-memory map to store blacklisted token IDs with their expiration time.
// mu protects concurrent access to the blacklist map.
type JWT struct {
	AdminRole      string
	PermissionsMap map[string][]string
	SkipList       []string

	auth      jwtAuth.Auth
	blacklist map[string]time.Time
	mu        sync.RWMutex
}

// New is a JWT middleware constructor.
//
// adminRole is the maximum permission role, that allows everything by default.
// claimsKey is the authentication key used by claims.
// tokenSecret the secret key to verify the integrity and authenticity of the JWT
// tokenMaxAge is the max duration of a token, in nanoseconds.
// skipList is the list of endpoints that are ignored for JWT verification.
// permissionsMap is the list of endpoints, associated to the allowed permission roles.
func New(
	adminRole string,
	skipList []string,
	permissionsMap map[string][]string,
	authentication jwtAuth.Auth,
) JWT {
	return JWT{
		AdminRole:      adminRole,
		PermissionsMap: permissionsMap,
		SkipList:       skipList,
		auth:           authentication,
		blacklist:      make(map[string]time.Time),
	}
}
