package repo

import (
	"context"
	"database/sql"
	"fmt"
	"my_project/delivery_bot/backend/auth-service/internal/domain"
	"my_project/delivery_bot/backend/auth-service/pkg/auth_errors"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	SetEmailVerified(ctx context.Context, userID uuid.UUID) error
	GetByUserName(ctx context.Context, username string) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetById(ctx context.Context, id uuid.UUID) (*domain.User, error)
	UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error
}

type UserRepo struct {
	db *sql.DB
}

func NewUserRepo(db *sql.DB) *UserRepo {
	return &UserRepo{db: db}
}

func (r *UserRepo) Create(ctx context.Context, user *domain.User) error {
	query := `
		INSERT INTO users (name, email, password_hash, role, street, house, apartment, entrance, email_verified)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id, created_at, updated_at
	`
	id := uuid.New()
	err := r.db.QueryRowContext(ctx, query,
		user.UserName,
		user.Email,
		user.Password,
		user.Role,
		user.Street,
		user.House,
		user.Apartment,
		user.Entrance,
		user.EmailVerified,
	).Scan(&id, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		// Обработка конфликтов уникальности name/email
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			// Для любых уникальных ограничений на name/email возвращаем "user already exists"
			return fmt.Errorf("%w", auth_errors.ErrUserAlreadyExists)
		}
		return err
	}
	user.Id = id
	return nil
}

func (r *UserRepo) SetEmailVerified(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE users
		SET email_verified = TRUE,
		    updated_at = NOW()
		WHERE id = $1
	`, userID)
	return err
}

func (r *UserRepo) GetByUserName(ctx context.Context, username string) (*domain.User, error) {
	query := `
		SELECT
			id,
			name,
			email,
			password_hash,
			role,
			COALESCE(street, '')   AS street,
			COALESCE(house, '')    AS house,
			COALESCE(apartment, '') AS apartment,
			COALESCE(entrance, '') AS entrance,
			is_active,
			email_verified,
			created_at,
			updated_at
		FROM users
		WHERE name = $1
	`
	var user domain.User
	if err := r.db.QueryRowContext(ctx, query, username).Scan(
		&user.Id,
		&user.UserName,
		&user.Email,
		&user.Password,
		&user.Role,
		&user.Street,
		&user.House,
		&user.Apartment,
		&user.Entrance,
		&user.IsActive,
		&user.EmailVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%w", auth_errors.ErrUserNotFound)
		}
		return nil, fmt.Errorf("get user by username: %w", err)
	}
	return &user, nil
}

func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT
			id,
			name,
			email,
			password_hash,
			role,
			COALESCE(street, '')   AS street,
			COALESCE(house, '')    AS house,
			COALESCE(apartment, '') AS apartment,
			COALESCE(entrance, '') AS entrance,
			is_active,
			email_verified,
			created_at,
			updated_at
		FROM users
		WHERE email = $1
	`
	var user domain.User
	if err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.Id,
		&user.UserName,
		&user.Email,
		&user.Password,
		&user.Role,
		&user.Street,
		&user.House,
		&user.Apartment,
		&user.Entrance,
		&user.IsActive,
		&user.EmailVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%w", auth_errors.ErrUserNotFound)
		}
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return &user, nil
}

func (r *UserRepo) GetById(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
		SELECT
			id,
			name,
			email,
			password_hash,
			role,
			COALESCE(street, '')   AS street,
			COALESCE(house, '')    AS house,
			COALESCE(apartment, '') AS apartment,
			COALESCE(entrance, '') AS entrance,
			is_active,
			email_verified,
			created_at,
			updated_at
		FROM users
		WHERE id = $1
	`
	var user domain.User
	if err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.Id,
		&user.UserName,
		&user.Email,
		&user.Password,
		&user.Role,
		&user.Street,
		&user.House,
		&user.Apartment,
		&user.Entrance,
		&user.IsActive,
		&user.EmailVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%w", auth_errors.ErrUserNotFound)
		}
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return &user, nil
}

func (r *UserRepo) UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	query := `
		UPDATE users
		SET password_hash = $1,
		    updated_at = NOW()
		WHERE id = $2
	`
	_, err := r.db.ExecContext(ctx, query, passwordHash, userID)
	return err
}
