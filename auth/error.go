package auth

type GuamError struct {
	Detail  string
	Message ErrorMessage
}

func (e *GuamError) Error() string {
	return string(e.Message) + ": " + e.Detail
}

func (e *GuamError) Is(target error) bool {
	return e.Error() == target.Error()
}

func NewGuamError(errorMsg ErrorMessage, detail *string) *GuamError {
	if detail == nil {
		return &GuamError{Message: errorMsg}
	}
	return &GuamError{Message: errorMsg, Detail: *detail}
}

type ErrorMessage string

const (
	AUTH_INVALID_SESSION_ID ErrorMessage = "AUTH_INVALID_SESSION_ID"
	AUTH_INVALID_PASSWORD   ErrorMessage = "AUTH_INVALID_PASSWORD"
	AUTH_DUPLICATE_KEY_ID   ErrorMessage = "AUTH_DUPLICATE_KEY_ID"
	AUTH_INVALID_KEY_ID     ErrorMessage = "AUTH_INVALID_KEY_ID"
	AUTH_INVALID_USER_ID    ErrorMessage = "AUTH_INVALID_USER_ID"
	AUTH_INVALID_REQUEST    ErrorMessage = "AUTH_INVALID_REQUEST"
	AUTH_NOT_AUTHENTICATED  ErrorMessage = "AUTH_NOT_AUTHENTICATED"
	REQUEST_UNAUTHORIZED    ErrorMessage = "REQUEST_UNAUTHORIZED"
	UNKNOWN_ERROR           ErrorMessage = "UNKNOWN_ERROR"
	AUTH_OUTDATED_PASSWORD  ErrorMessage = "AUTH_OUTDATED_PASSWORD"
)
