package repo

import (
	"errors"
	"sync"

	"my_project/delivery_bot/backend/auth-service/internal/domain"
)

type User interface {
	Create(user domain.User) error
	GetByUserName(user string) (*domain.User, error)
}

type UserRepo struct {
	users  map[string]domain.User
	mu     sync.RWMutex
	lastId int64
}

func NewUserRepo() *UserRepo {
	return &UserRepo{
		users: make(map[string]domain.User),
	}
}

func (u *UserRepo) Create(user domain.User) error {
	u.mu.RLock()
	defer u.mu.RUnlock()

	if _, exists := u.users[user.UserName]; exists {
		return errors.New("user already exists")
	}

	u.lastId++
	user.Id = u.lastId
	u.users[user.UserName] = user
	return nil
}

func (u *UserRepo) GetByUserName(username string) (*domain.User, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	userResponse, ok := u.users[username]
	if !ok {
		return nil, errors.New("user not found")
	}
	return &userResponse, nil
}
