package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hasanm95/go-auth-gatekeeper/internal/config"
	"github.com/hasanm95/go-auth-gatekeeper/internal/model"
)

type UserService struct {
	repo model.UserRepository
	cfg *config.Config
}

func NewUserService (r model.UserRepository, cfg *config.Config) *UserService{
	return &UserService{repo: r, cfg: cfg}
}

func (s *UserService) GetUser(ctx context.Context, email string) (*model.User, error) {
	return s.repo.GetUserByEmail(ctx, email)
}

func (s *UserService) RegisterUser(ctx context.Context, email string, password string) (*model.User, error){
	_, err := s.repo.GetUserByEmail(ctx, email)

	if err == nil {
		return nil, fmt.Errorf("user already exists with email: %v", email)
	}

	if !errors.Is(err, model.ErrUserNotFound) {
		return nil, fmt.Errorf("checking existing user: %w", err)
	}

	passwordHash, err := HashPassword(password)

	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	return s.repo.CreateUser(ctx, email, passwordHash)
}

func (s *UserService) LoginUser(ctx context.Context, email, password string) (string, string, error) {
	user, err := s.repo.GetUserByEmail(ctx, email)

	if err != nil {
		if !errors.Is(err, model.ErrUserNotFound) {
			return "", "", model.ErrInvalidCredentials
		}
		return "", "", err 
	}



	isPasswordOk := CheckPassword(password, user.PasswordHash)

	if !isPasswordOk {
		return "", "", model.ErrInvalidCredentials
	} 

	accessToken, err := GenerateToken(user.ID, s.cfg.SecretKey, 15 * time.Minute, "access")

	if err != nil {
		return "", "", err
	}

	refreshToken, err := GenerateToken(user.ID, s.cfg.SecretKey, 7 * 24 * time.Hour, "refresh")

	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}