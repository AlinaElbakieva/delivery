package domain

import "time"

type OTP struct {
	Code      string
	ExpiresAt time.Time
}
