package model

import (
	"context"
	"time"
)

type User struct {
	ID int64 `json:"id"`
	Email string `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	PasswordHash string `json:"-"`
	IsVerified bool `json:"is_verified"`
}

type RegisterRequest struct {
	Email string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,gte=8"`
}

type RegisterResponse struct {
	ID int64 `json:"id"`
	Email string `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	IsVerified bool `json:"is_verified"`
}

type UserRepository interface {
	CreateUser (ctx context.Context, email string, password string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByID(ctx context.Context, id int64) (*User, error)
	MarkUserVerified(ctx context.Context, userID int64) error
	UpdatePassword(ctx context.Context, userID int64, newPassword string) error
}

type LoginRequest struct {
	Email string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,gte=8"`
}

type LoginResponse struct {
	AccessToken string `json:"access_token"`
	IsVerified bool `json:"is_verified"`
}
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPasswordRequest struct {
	NewPassword string `json:"new_password" validate:"required,gte=8"`
}