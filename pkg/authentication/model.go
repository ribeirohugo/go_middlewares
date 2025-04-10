package authentication

type ClaimsKey string

// Claims holds authentication and mapped data from a context.
type Claims struct {
	UserID string
	Role   string
}
