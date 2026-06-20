package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/hasanm95/go-auth-gatekeeper/internal/model"
	"github.com/hasanm95/go-auth-gatekeeper/internal/utils"
)

type UserService struct {
	repo model.UserRepository
}

func NewUserService (r model.UserRepository) *UserService{
	return &UserService{repo: r}
}

func (s *UserService) GetUser(ctx context.Context, email string) (*model.User, error) {
	return s.repo.GetUserByEmail(ctx, email)
}

func (s *UserService) RegisterUser(ctx context.Context, email string, password string) (*model.User, error){
	user, err := s.repo.GetUserByEmail(ctx, email)

	fmt.Print(user)

	if err == nil {
		return nil, fmt.Errorf("user already exists with email: %v", email)
	}

	if !errors.Is(err, model.ErrUserNotFound) {
		return nil, fmt.Errorf("checking existing user: %w", err)
	}

	passwordHash, err := utils.HashPassword(password)

	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	return s.repo.CreateUser(ctx, email, passwordHash)
}