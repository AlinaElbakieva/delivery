package repo

import (
	"context"
	"database/sql"

	"my_project/delivery_bot/backend/auth-service/internal/domain"
)

type PostgresUserRepo struct {
	db *sql.DB
}

func (r *PostgresUserRepo) Create(ctx context.Context, user domain.User) (domain.User, error) {
	query := `
	INSERT INTO users (username, email)
	VALUES ($1, $2)
	RETURNING id
	`

	err := r.db.QueryRowContext(
		ctx,
		query,
		user.UserName,
		user.Email,
	).Scan(&user.Id)

	if err != nil {
		return domain.User{}, err
	}

	return user, nil
}
