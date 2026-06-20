package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/hasanm95/go-auth-gatekeeper/internal/config"
	"github.com/hasanm95/go-auth-gatekeeper/internal/model"
	"github.com/redis/go-redis/v9"
)

type UserService struct {
	repo model.UserRepository
	cfg *config.Config
	redisClient *redis.Client
}

func NewUserService (r model.UserRepository, cfg *config.Config, redisClient *redis.Client) *UserService{
	return &UserService{repo: r, cfg: cfg, redisClient: redisClient}
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

func (s *UserService) RefreshToken(ctx context.Context, refreshTokenString string) (string, error) {
	claims, err := ValidateToken(refreshTokenString, s.cfg.SecretKey)

	if err != nil {
		return "", err
	}

	if claims.TokenType != "refresh" {
		return "", fmt.Errorf("invalid token type")
	}

	isBlackListed, err := s.IsTokenBlackListed(ctx, refreshTokenString)

	if err != nil {
		return "", err
	}

	if isBlackListed {
		return "", fmt.Errorf("token has been revoked")
	}

	newAccessToken, err := GenerateToken(claims.UserID, s.cfg.SecretKey, 15 * time.Minute, "access")

	if err != nil {
		return "", err
	}

	return newAccessToken, nil
}

func (s *UserService) BlacklistToken(ctx context.Context, tokenString string, expiresAt time.Time) error{
	ttl := time.Until(expiresAt)

	if ttl < 0 {
		return nil
	}

	key := "blacklist:" + tokenString

	err := s.redisClient.Set(ctx, key, "true", ttl).Err()

	return err
}

func (s *UserService) IsTokenBlackListed(ctx context.Context, tokenString string) (bool, error) {
	key := "blacklist:" + tokenString
	result, err := s.redisClient.Exists(ctx, key).Result()

	if err != nil {
		return false, fmt.Errorf("failed to check key existence: %w", err)
	}

	return result > 0, nil
}

func (s *UserService) LogoutUser(ctx context.Context, accessToken, refreshToken string) error {
    var firstErr error

    if accessToken != "" {
        if accessClaims, err := ValidateToken(accessToken, s.cfg.SecretKey); err == nil {
            if blacklistErr := s.BlacklistToken(ctx, accessToken, accessClaims.ExpiresAt.Time); blacklistErr != nil {
                log.Printf("failed to blacklist access token: %v", blacklistErr)
                firstErr = blacklistErr
            }
        }
    }

    if refreshToken != "" {
        if refreshClaims, err := ValidateToken(refreshToken, s.cfg.SecretKey); err == nil {
            if blacklistErr := s.BlacklistToken(ctx, refreshToken, refreshClaims.ExpiresAt.Time); blacklistErr != nil {
                log.Printf("failed to blacklist refresh token: %v", blacklistErr)
                if firstErr == nil {
                    firstErr = blacklistErr
                }
            }
        }
    }

    return firstErr
}