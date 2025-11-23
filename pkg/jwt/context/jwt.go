package context

import (
	"context"
	"fmt"
	"time"

	jwtAuth "github.com/ribeirohugo/go_middlewares/pkg/jwt"
)

// GetClaims allows to extract claims from context.
func (j *JWT) GetClaims(ctx context.Context) (jwtAuth.Claims, error) {
	return j.auth.ParseClaims(ctx)
}

// Logout removes claims from the context and adds the token to the blacklist, effectively logging the user out.
func (j *JWT) Logout(ctx context.Context) (context.Context, error) {
	claims, err := j.auth.ParseClaims(ctx)
	if err != nil {
		// If we can't parse claims, still return context with nil value
		return context.WithValue(ctx, j.auth.ClaimsKey, nil), nil
	}

	// Add token ID to blacklist with its expiration time
	j.mu.Lock()
	j.blacklist[claims.ID] = time.Unix(claims.ExpiresAt, 0)
	j.mu.Unlock()

	// Clean up expired tokens from blacklist
	go j.cleanupExpiredTokens()

	return context.WithValue(ctx, j.auth.ClaimsKey, nil), nil
}

// cleanupExpiredTokens removes expired tokens from the blacklist to prevent memory leaks.
func (j *JWT) cleanupExpiredTokens() {
	now := time.Now()

	j.mu.Lock()
	defer j.mu.Unlock()

	for tokenID, expiresAt := range j.blacklist {
		if now.After(expiresAt) {
			delete(j.blacklist, tokenID)
		}
	}
}

// isBlacklisted checks if a token ID is in the blacklist.
func (j *JWT) isBlacklisted(tokenID string) bool {
	j.mu.RLock()
	defer j.mu.RUnlock()

	expiresAt, exists := j.blacklist[tokenID]
	if !exists {
		return false
	}

	// Check if the blacklist entry has expired
	if time.Now().After(expiresAt) {
		return false
	}

	return true
}

func (j *JWT) Login(_ context.Context, subject, issuer, audience, role string) (string, error) {
	tokenString, err := j.auth.ClaimsSignedToken(subject, issuer, audience, role)
	if err != nil {
		return "", fmt.Errorf("login failed: %v", err)
	}

	return tokenString, err
}
