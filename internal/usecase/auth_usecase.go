package usecase

import (
	"errors"
	"fmt"
	"math/rand"
	"time"

	"my_project/delivery_bot/backend/auth-service/internal/crypto"
	"my_project/delivery_bot/backend/auth-service/internal/domain"
	"my_project/delivery_bot/backend/auth-service/internal/repo"

	"golang.org/x/crypto/bcrypt"
)

type AuthUseCase struct {
	repo    *repo.UserRepo
	otpRepo *repo.OTPRepo
	jwt     *crypto.JWTService
	sendOTP func(username, code string) error //todo
}

func NewAuthUseCase(repo *repo.UserRepo, otpRepo *repo.OTPRepo, jwt *crypto.JWTService, sendOTP func(username, code string) error) *AuthUseCase {
	return &AuthUseCase{repo: repo, otpRepo: otpRepo, jwt: jwt, sendOTP: sendOTP}
}
func (a *AuthUseCase) Register(username, password, role string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user := domain.User{
		UserName:  username,
		Password:  string(hash),
		Role:      role,
		CreatedAt: time.Now(),
	}
	return a.repo.Create(user)
}

func (a *AuthUseCase) Login(username, password string) error {
	user, err := a.repo.GetByUserName(username)
	if err != nil {
		return errors.New("invalid credentials")
	}
	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
		return errors.New("invalid credentials")
	}

	// Генерация OTP
	code := fmt.Sprintf("%06d", rand.Intn(1000000))
	a.otpRepo.Save(username, code, 5*time.Minute)
	if a.sendOTP == nil {
		return errors.New("internal server error: sendOTP not configured")
	}
	return a.sendOTP(username, code)
}

func (a *AuthUseCase) VerifyOTP(username, code string) (string, string, error) {
	storedCode, ok := a.otpRepo.Get(username)
	if !ok || storedCode != code {
		return "", "", errors.New("invalid OTP")
	}
	user, err := a.repo.GetByUserName(username)
	if err != nil {
		return "", "", err
	}
	a.otpRepo.Delete(username)

	access, err := a.jwt.GenerateToken(user.Id, user.UserName, user.Role, crypto.AccessToken)
	if err != nil {
		return "", "", err
	}
	refresh, err := a.jwt.GenerateToken(user.Id, user.UserName, user.Role, crypto.RefreshToken)
	if err != nil {
		return "", "", err
	}
	return access, refresh, nil
}

func (a *AuthUseCase) RefreshToken(refreshToken string) (string, string, error) {
	_, claims, err := a.jwt.ValidateToken(refreshToken, crypto.RefreshToken)
	if err != nil {
		return "", "", errors.New("invalid refresh token")
	}
	userID := int64(claims["sub"].(float64))
	username := claims["username"].(string)
	role := claims["role"].(string)

	access, err := a.jwt.GenerateToken(userID, username, role, crypto.AccessToken)
	if err != nil {
		return "", "", err
	}
	newRefresh, err := a.jwt.GenerateToken(userID, username, role, crypto.RefreshToken)
	if err != nil {
		return "", "", err
	}
	return access, newRefresh, nil
}
