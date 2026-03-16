package auth_errors

import "errors"

var (
	ErrUserNotFound         = errors.New("user not found")
	ErrUserAlreadyExists    = errors.New("user already exists")
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrEmailNotVerified     = errors.New("email not verified")
	ErrInvalidOTP           = errors.New("invalid OTP")
	ErrSendOTPNotConfigured = errors.New("sendOTP not configured")
	ErrInvalidRefreshToken  = errors.New("invalid refresh token")
	ErrInvalidRequest       = errors.New("invalid request")
	ErrVerifyOTP            = errors.New("error verify otp")
)
