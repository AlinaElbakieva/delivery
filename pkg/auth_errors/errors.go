package auth_errors

import "errors"

var (
	ErrInternal            = errors.New("internal error")
	ErrInvalidToken        = errors.New("invalid token")
	ErrUserNotFound        = errors.New("user not found")
	ErrUserAlreadyExists   = errors.New("user already exists")
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrEmailNotVerified    = errors.New("email not verified")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrInvalidRequest      = errors.New("invalid request")
)
