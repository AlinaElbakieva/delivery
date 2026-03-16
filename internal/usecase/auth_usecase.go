package usecase

import (
	"context"
	"errors"
	"fmt"
	"my_project/delivery_bot/backend/auth-service/internal/crypto"
	"my_project/delivery_bot/backend/auth-service/internal/domain"
	"my_project/delivery_bot/backend/auth-service/pkg/auth_errors"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	SetEmailVerified(ctx context.Context, userID uuid.UUID) error
	GetByUserName(ctx context.Context, username string) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetById(ctx context.Context, id uuid.UUID) (*domain.User, error)
	UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error
}

type EmailConfirmRepository interface {
	Save(ctx context.Context, token uuid.UUID, userID uuid.UUID, expiresAt time.Time) error
	GetUserID(ctx context.Context, token uuid.UUID) (uuid.UUID, bool, error)
	Delete(ctx context.Context, token uuid.UUID) error
}

type PasswordResetRepository interface {
	Save(ctx context.Context, token uuid.UUID, userID uuid.UUID, expiresAt time.Time) error
	GetUserID(ctx context.Context, token uuid.UUID) (uuid.UUID, bool, error)
	Delete(ctx context.Context, token uuid.UUID) error
}

type JWTService interface {
	GenerateToken(userId uuid.UUID, username, role string, tokenType crypto.TokenType) (string, error)
	ValidateToken(token string, tokenType crypto.TokenType) (*crypto.AuthClaims, error)
}

type AuthUseCase struct {
	userRepo             UserRepository
	emailConfirmRepo     EmailConfirmRepository
	passwordResetRepo    PasswordResetRepository
	jwt                  JWTService
	logger               *zap.Logger
	confirmBaseURL       string
	resetPasswordBaseURL string
	sendConfirmEmail     func(email, link string) error
	sendResetEmail       func(email, link string) error
}

func NewAuthUseCase(
	userRepo UserRepository,
	emailConfirmRepo EmailConfirmRepository,
	passwordResetRepo PasswordResetRepository,
	jwt JWTService,
	confirmBaseURL string,
	resetPasswordBaseURL string,
	sendConfirmEmail func(email, link string) error,
	sendResetEmail func(email, link string) error,
	logger *zap.Logger,
) *AuthUseCase {
	return &AuthUseCase{
		userRepo:             userRepo,
		emailConfirmRepo:     emailConfirmRepo,
		passwordResetRepo:    passwordResetRepo,
		jwt:                  jwt,
		logger:               logger,
		confirmBaseURL:       confirmBaseURL,
		resetPasswordBaseURL: resetPasswordBaseURL,
		sendConfirmEmail:     sendConfirmEmail,
		sendResetEmail:       sendResetEmail,
	}
}

const defaultUserRole = "USER"

func (a *AuthUseCase) Register(ctx context.Context, username, password, _ string, email string) error {
	if existing, _ := a.userRepo.GetByEmail(ctx, email); existing != nil {
		return fmt.Errorf("%w", auth_errors.ErrUserAlreadyExists)
	}

	if existing, _ := a.userRepo.GetByUserName(ctx, username); existing != nil {
		return fmt.Errorf("%w", auth_errors.ErrUserAlreadyExists)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		a.logger.Warn("hash password failed", zap.Error(err))
		return errors.New("error register user")
	}

	user := domain.User{
		UserName:      username,
		Password:      string(hash),
		Email:         email,
		Role:          defaultUserRole,
		IsActive:      true,
		EmailVerified: false,
		CreatedAt:     time.Now(),
	}

	if err := a.userRepo.Create(ctx, &user); err != nil {
		if errors.Is(err, auth_errors.ErrUserAlreadyExists) {
			return fmt.Errorf("%w", auth_errors.ErrUserAlreadyExists)
		}
		a.logger.Warn("create user error", zap.Error(err))
		return errors.New("error register user")
	}

	token := uuid.New()
	expiresAt := time.Now().Add(24 * time.Hour)
	if err := a.emailConfirmRepo.Save(ctx, token, user.Id, expiresAt); err != nil {
		a.logger.Warn("save email confirm token failed", zap.Error(err))
		return nil
	}

	if a.sendConfirmEmail != nil && a.confirmBaseURL != "" {
		link := a.confirmBaseURL + "?token=" + token.String()
		if err := a.sendConfirmEmail(email, link); err != nil {
			a.logger.Warn("send confirm email failed", zap.Error(err))
		}
	}

	return nil
}

func (a *AuthUseCase) Login(ctx context.Context, email, password string) (string, string, error) {
	user, err := a.userRepo.GetByEmail(ctx, email)
	if err != nil {
		a.logger.Error("error get user by email", zap.Error(err))
		return "", "", fmt.Errorf("login: %w", auth_errors.ErrInvalidCredentials)
	}
	a.logger.Info("login attempt", zap.String("user_id", user.Id.String()), zap.String("email", user.Email))
	if !user.EmailVerified {
		a.logger.Error("email not verified")
		return "", "", fmt.Errorf("login: %w", auth_errors.ErrEmailNotVerified)
	}

	if !user.IsActive {
		a.logger.Error("inactive user login attempt", zap.String("user_id", user.Id.String()), zap.String("email", user.Email))
		return "", "", fmt.Errorf("login: %w", auth_errors.ErrInvalidCredentials)
	}

	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
		a.logger.Error("invalid credentials")
		return "", "", fmt.Errorf("login: %w", auth_errors.ErrInvalidCredentials)
	}

	access, err := a.jwt.GenerateToken(user.Id, user.UserName, user.Role, crypto.AccessToken)
	if err != nil {
		a.logger.Error("error generate access token", zap.Error(err))
		return "", "", auth_errors.ErrInternal
	}

	refresh, err := a.jwt.GenerateToken(user.Id, user.UserName, user.Role, crypto.RefreshToken)
	if err != nil {
		a.logger.Error("error generate refresh token", zap.Error(err))
		return "", "", auth_errors.ErrInternal
	}

	return access, refresh, nil
}

func (a *AuthUseCase) ConfirmEmail(ctx context.Context, token uuid.UUID) error {
	userID, ok, err := a.emailConfirmRepo.GetUserID(ctx, token)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w", auth_errors.ErrInternal)
	}
	if err := a.userRepo.SetEmailVerified(ctx, userID); err != nil {
		return err
	}
	_ = a.emailConfirmRepo.Delete(ctx, token)
	return nil
}

func (a *AuthUseCase) ForgotPassword(ctx context.Context, email string) error {
	user, err := a.userRepo.GetByEmail(ctx, email)
	if err != nil || user == nil {
		a.logger.Warn("forgot password: user not found or error", zap.Error(err))
		return nil
	}

	token := uuid.New()
	expiresAt := time.Now().Add(1 * time.Hour)
	if err := a.passwordResetRepo.Save(ctx, token, user.Id, expiresAt); err != nil {
		a.logger.Warn("save password reset token failed", zap.Error(err))
		return nil
	}

	if a.sendResetEmail != nil && a.resetPasswordBaseURL != "" {
		link := a.resetPasswordBaseURL + "?token=" + token.String()
		if err := a.sendResetEmail(email, link); err != nil {
			a.logger.Warn("send reset password email failed", zap.Error(err))
		}
	}
	return nil
}

func (a *AuthUseCase) ResetPassword(ctx context.Context, token uuid.UUID, newPassword string) error {
	userID, ok, err := a.passwordResetRepo.GetUserID(ctx, token)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w", auth_errors.ErrInternal)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		a.logger.Warn("hash new password failed", zap.Error(err))
		return errors.New("error reset password")
	}

	user, err := a.userRepo.GetById(ctx, userID)
	if err != nil {
		return err
	}
	user.Password = string(hash)

	if err := a.userRepo.UpdatePassword(ctx, userID, user.Password); err != nil {
		return err
	}

	_ = a.passwordResetRepo.Delete(ctx, token)
	return nil
}

func (a *AuthUseCase) RefreshToken(ctx context.Context, refreshToken string) (string, string, error) {
	claims, err := a.jwt.ValidateToken(refreshToken, crypto.RefreshToken)
	if err != nil {
		return "", "", fmt.Errorf("%w", auth_errors.ErrInvalidRefreshToken)
	}

	userId, err := uuid.Parse(claims.RegisteredClaims.Subject)
	if err != nil {
		a.logger.Warn("invalid subject in refresh token", zap.Error(err))
		return "", "", fmt.Errorf("%w", auth_errors.ErrInvalidRefreshToken)
	}

	username := claims.Username
	role := claims.Role

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
