package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port           string
	JWTPrivateKey  string
	JWTPublicKey   string
	JWTIssuer      string
	AccessTTL      time.Duration
	RefreshTTL     time.Duration
	OTPTTL         time.Duration
	OTPSenderEmail string // для реальной отправки email
}

func LoadConfig() (*Config, error) {
	cfg := &Config{}

	// Порт
	port := os.Getenv("API_PORT")
	if port == "" {
		port = "8080"
	}
	cfg.Port = port

	// Пути к ключам
	cfg.JWTPrivateKey = os.Getenv("JWT_PRIVATE_KEY")
	if cfg.JWTPrivateKey == "" {
		cfg.JWTPrivateKey = "private.pem"
	}

	cfg.JWTPublicKey = os.Getenv("JWT_PUBLIC_KEY")
	if cfg.JWTPublicKey == "" {
		cfg.JWTPublicKey = "public.pem"
	}

	// Issuer токена
	issuer := os.Getenv("JWT_ISSUER")
	if issuer == "" {
		issuer = "auth-service"
	}
	cfg.JWTIssuer = issuer

	// TTL токенов
	accessTTLStr := os.Getenv("ACCESS_TTL_MINUTES")
	accessTTL := 15
	if accessTTLStr != "" {
		if v, err := strconv.Atoi(accessTTLStr); err == nil {
			accessTTL = v
		}
	}
	cfg.AccessTTL = time.Duration(accessTTL) * time.Minute

	refreshTTLStr := os.Getenv("REFRESH_TTL_HOURS")
	refreshTTL := 24 * 7
	if refreshTTLStr != "" {
		if v, err := strconv.Atoi(refreshTTLStr); err == nil {
			refreshTTL = v
		}
	}
	cfg.RefreshTTL = time.Duration(refreshTTL) * time.Hour

	otpTTLStr := os.Getenv("OTP_TTL_MINUTES")
	otpTTL := 5
	if otpTTLStr != "" {
		if v, err := strconv.Atoi(otpTTLStr); err == nil {
			otpTTL = v
		}
	}
	cfg.OTPTTL = time.Duration(otpTTL) * time.Minute

	cfg.OTPSenderEmail = os.Getenv("OTP_SENDER_EMAIL")
	if cfg.OTPSenderEmail == "" {
		cfg.OTPSenderEmail = "no-reply@example.com"
	}

	return cfg, nil
}
