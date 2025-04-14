package authentication

import "github.com/google/uuid"

type ClaimsKey string

// Claims holds authentication data.
type Claims struct {
	ID        uuid.UUID `json:"id"`
	Subject   string    `json:"subject"`
	Role      string    `json:"role"`
	CreatedAt int64     `json:"created_at"`
	ExpiresAt int64     `json:"expires_at"`
}
