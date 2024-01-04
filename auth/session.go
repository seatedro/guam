package auth

import "github.com/rohitp934/guam/utils"

func IsValidDatabaseSession(session *SessionSchema) bool {
	return utils.IsWithinExpiration(session.IdleExpires)
}
