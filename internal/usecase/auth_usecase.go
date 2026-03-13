package usecase

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"my_project/delivery_bot/backend/auth-service/internal/crypto"
	"my_project/delivery_bot/backend/auth-service/internal/domain"
	"my_project/delivery_bot/backend/auth-service/pkg/auth_errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	SaveToken(ctx context.Context, id uuid.UUID, access, refresh string) error
	GetByUserName(ctx context.Context, username string) (*domain.User, error)
	GetById(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

type OTPRepository interface {
	Save(ctx context.Context, username, code string, ttl time.Duration) error
	Get(ctx context.Context, username string) (string, bool, error)
	Delete(ctx context.Context, username string) error
}

type JWTService interface {
	GenerateToken(userId uuid.UUID, username, role string, tokenType crypto.TokenType) (string, error)
	ValidateToken(token string, tokenType crypto.TokenType) (*jwt.Token, jwt.MapClaims, error)
}

type AuthUseCase struct {
	userRepo UserRepository
	otpRepo  OTPRepository
	jwt      JWTService
	sendOTP  func(username, code string) error
	logger   *zap.Logger
}

func NewAuthUseCase(userRepo UserRepository, otpRepo OTPRepository, jwt JWTService, sendOTP func(username, code string) error, logger *zap.Logger) *AuthUseCase {
	return &AuthUseCase{
		userRepo: userRepo,
		otpRepo:  otpRepo,
		jwt:      jwt,
		sendOTP:  sendOTP,
		logger:   logger,
	}
}

func (a *AuthUseCase) Register(ctx context.Context, username, password, role, email string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		a.logger.Info(fmt.Sprintf("hash password: %v", err))
		return errors.New("error register user")
	}

	user := domain.User{
		UserName:  username,
		Password:  string(hash),
		Email:     email,
		Role:      role,
		CreatedAt: time.Now(),
	}

	if err := a.userRepo.Create(ctx, &user); err != nil {
		a.logger.Info(fmt.Sprintf("create user error: %v", err))
		return errors.New("error register user")
	}
	return nil
}

func (a *AuthUseCase) Login(ctx context.Context, username, password string) error {
	a.logger.Info(fmt.Sprintf("username and password:%+v %+v ", username, password))
	user, err := a.userRepo.GetByUserName(ctx, username)
	if err != nil {
		return fmt.Errorf("login: %w", auth_errors.ErrInvalidCredentials)
	}

	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
		return fmt.Errorf("login: %w", auth_errors.ErrInvalidCredentials)
	}

	code := fmt.Sprintf("%06d", rand.Intn(1000000))
	if err := a.otpRepo.Save(ctx, username, code, 5*time.Minute); err != nil {
		return err
	}

	if a.sendOTP == nil {
		return fmt.Errorf("%w", auth_errors.ErrSendOTPNotConfigured)
	}
	return a.sendOTP(username, code)
}

func (a *AuthUseCase) VerifyOTP(ctx context.Context, username, code string) (string, string, error) {
	storedCode, ok, err := a.otpRepo.Get(ctx, username)
	if err != nil {
		return "", "", err
	}
	if !ok || storedCode != code {
		return "", "", fmt.Errorf("%w", auth_errors.ErrInvalidOTP)
	}

	user, err := a.userRepo.GetByUserName(ctx, username)
	if err != nil {
		return "", "", err
	}

	if err := a.otpRepo.Delete(ctx, username); err != nil {
		return "", "", err
	}

	access, err := a.jwt.GenerateToken(user.Id, user.UserName, user.Role, crypto.AccessToken)
	if err != nil {
		a.logger.Error("error generate access token", zap.Error(err))
		return "", "", auth_errors.ErrVerifyOTP
	}

	refresh, err := a.jwt.GenerateToken(user.Id, user.UserName, user.Role, crypto.RefreshToken)
	if err != nil {
		a.logger.Error("error generate refresh token", zap.Error(err))
		return "", "", auth_errors.ErrVerifyOTP
	}

	err = a.userRepo.SaveToken(ctx, user.Id, access, refresh)
	if err != nil {
		a.logger.Error("error save access_token and refresh_token", zap.Error(err))
		return "", "", auth_errors.ErrVerifyOTP
	}
	return access, refresh, nil
}

func (a *AuthUseCase) RefreshToken(ctx context.Context, refreshToken string) (string, string, error) {
	_, claims, err := a.jwt.ValidateToken(refreshToken, crypto.RefreshToken)
	if err != nil {
		return "", "", fmt.Errorf("%w", auth_errors.ErrInvalidRefreshToken)
	}

	userId, err := uuid.Parse(claims["sub"].(string))
	username := claims["username"].(string)
	role := claims["role"].(string)

	access, err := a.jwt.GenerateToken(userId, username, role, crypto.AccessToken)
	if err != nil {
		a.logger.Error("error generate access token", zap.Error(err))
		return "", "", auth_errors.ErrInvalidRefreshToken
	}
	refresh, err := a.jwt.GenerateToken(userId, username, role, crypto.RefreshToken)
	if err != nil {
		a.logger.Error("error generate refresh token", zap.Error(err))
		return "", "", auth_errors.ErrInvalidRefreshToken
	}
	return access, refresh, nil
}
