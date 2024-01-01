package auth

func IsValidDatabaseSession(session SessionSchema) bool {
	return IsWithinExpiration(session.IdleExpires)
}
