package auth

import "github.com/seatedro/guam/utils"

func IsValidDatabaseSession(session *SessionSchema) bool {
	return utils.IsWithinExpiration(session.IdleExpires)
}
