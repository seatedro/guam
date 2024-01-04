package utils

import "time"

func IsWithinExpiration(expiration int64) bool {
	return time.Now().Before(time.Unix(0, expiration*int64(time.Millisecond)))
}
