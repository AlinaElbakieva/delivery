package repo

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type EmailConfirmRepository interface {
	Save(ctx context.Context, token uuid.UUID, userID uuid.UUID, expiresAt time.Time) error
	GetUserID(ctx context.Context, token uuid.UUID) (uuid.UUID, bool, error)
	Delete(ctx context.Context, token uuid.UUID) error
}

type EmailConfirmRepo struct {
	db *sql.DB
}

func NewEmailConfirmRepo(db *sql.DB) *EmailConfirmRepo {
	return &EmailConfirmRepo{db: db}
}

func (r *EmailConfirmRepo) Save(ctx context.Context, token uuid.UUID, userID uuid.UUID, expiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO email_confirm_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)`,
		token, userID, expiresAt,
	)
	return err
}

func (r *EmailConfirmRepo) GetUserID(ctx context.Context, token uuid.UUID) (uuid.UUID, bool, error) {
	var userID uuid.UUID
	var expiresAt time.Time
	err := r.db.QueryRowContext(ctx,
		`SELECT user_id, expires_at FROM email_confirm_tokens WHERE token = $1`,
		token,
	).Scan(&userID, &expiresAt)
	if err == sql.ErrNoRows {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	if time.Now().After(expiresAt) {
		return uuid.Nil, false, nil
	}
	return userID, true, nil
}

func (r *EmailConfirmRepo) Delete(ctx context.Context, token uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM email_confirm_tokens WHERE token = $1`, token)
	return err
}

