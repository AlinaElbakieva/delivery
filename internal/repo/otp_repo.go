package repo

import (
	"sync"
	"time"

	"my_project/delivery_bot/backend/auth-service/internal/domain"
)

type IsOTP interface {
	Save(username, code string, ttl time.Duration)
	Get(username string) (string, bool)
	Delete(username string)
}

type OTPRepo struct {
	data map[string]domain.OTP
	mu   sync.RWMutex
}

func NewOTPRepo() *OTPRepo {
	return &OTPRepo{
		data: make(map[string]domain.OTP),
	}
}

func (o *OTPRepo) Save(username, code string, ttl time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.data[username] = domain.OTP{
		Code:      code,
		ExpiresAt: time.Now().Add(ttl),
	}
}

func (o *OTPRepo) Get(username string) (string, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()

	otp, ok := o.data[username]
	if !ok || time.Now().After(otp.ExpiresAt) {
		return "", false
	}
	return otp.Code, true
}

func (o *OTPRepo) Delete(username string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.data, username)
}
