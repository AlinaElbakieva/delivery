package repo

import (
	"context"
	"database/sql"
	"fmt"
	"my_project/delivery_bot/backend/auth-service/internal/domain"
	"my_project/delivery_bot/backend/auth-service/pkg/auth_errors"

	"github.com/google/uuid"
)

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	SaveToken(ctx context.Context, access, refresh string) error
	GetByUserName(ctx context.Context, username string) (*domain.User, error)
	GetById(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

type UserRepo struct {
	db *sql.DB
}

func NewUserRepo(db *sql.DB) *UserRepo {
	return &UserRepo{db: db}
}

func (r *UserRepo) Create(ctx context.Context, user *domain.User) error {
	query := `
		INSERT INTO users (name, email, password_hash, role, street, house, apartment, entrance)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
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
	).Scan(&id, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return err
	}
	user.Id = id
	return nil
}
func (r *UserRepo) SaveToken(ctx context.Context, userId uuid.UUID, access, refresh string) error {
	query := `
		UPDATE users
		SET access_token = $1,
		    refresh_token = $2,
		    updated_at = NOW()
		WHERE id = $3
	`
	_, err := r.db.ExecContext(ctx, query, access, refresh, userId)
	if err != nil {
		return err
	}
	return nil
}
func (r *UserRepo) GetByUserName(ctx context.Context, username string) (*domain.User, error) {
	query := `
		SELECT id, name, email, password_hash, role, street, house, apartment, entrance, is_active, created_at, updated_at
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

func (r *UserRepo) GetById(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
		SELECT id, name, email, password_hash, role, street, house, apartment, entrance, is_active, created_at, updated_at
		FROM users
		WHERE id = $1 AND deleted_at IS NULL
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
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DeletedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%w", auth_errors.ErrUserNotFound)
		}
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return &user, nil
}
