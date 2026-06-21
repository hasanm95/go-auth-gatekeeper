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

	user, err := s.repo.CreateUser(ctx, email, passwordHash)

	if err != nil {
		return nil, err
	}

	verificationToken, err := GenerateToken(user.ID, s.cfg.SecretKey, 60 * time.Minute, "email_verification")

	if err != nil {
		log.Printf("failed to generate verification token for %s: %v", email, err)
	} else {
		verificationLink := s.cfg.BaseURL + "/verify?token=" + verificationToken
		log.Printf("VERIFICATION LINK for %s: %s", email, verificationLink)
	}

	return user, nil
}

func (s *UserService) LoginUser(ctx context.Context, email, password string) (string, string, bool, error) {
	user, err := s.repo.GetUserByEmail(ctx, email)

	if err != nil {
		if errors.Is(err, model.ErrUserNotFound) {
			return "", "", false, model.ErrInvalidCredentials
		}
		return "", "", false, fmt.Errorf("looking up user: %w", err)
	}

	isPasswordOk := CheckPassword(password, user.PasswordHash)

	if !isPasswordOk {
		return "", "", false, model.ErrInvalidCredentials
	} 

	accessToken, err := GenerateToken(user.ID, s.cfg.SecretKey, 15 * time.Minute, "access")

	if err != nil {
		return "", "", false, err
	}

	refreshToken, err := GenerateToken(user.ID, s.cfg.SecretKey, 7 * 24 * time.Hour, "refresh")

	if err != nil {
		return "", "", false, err
	}

	return accessToken, refreshToken, user.IsVerified, nil
}

func (s *UserService) RefreshToken(ctx context.Context, refreshTokenString string) (string, error) {
	claims, err := ValidateToken(refreshTokenString, s.cfg.SecretKey)

	if err != nil {
		return "", err
	}

	if claims.TokenType != "refresh" {
		return "", fmt.Errorf("invalid token type")
	}

	log.Printf("REFRESH - checking token: %s", refreshTokenString)
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

			log.Printf("LOGOUT - blacklisting access token: %s", accessToken)	
            if blacklistErr := s.BlacklistToken(ctx, accessToken, accessClaims.ExpiresAt.Time); blacklistErr != nil {
                log.Printf("failed to blacklist access token: %v", blacklistErr)
                firstErr = blacklistErr
            }
        }
    }

    if refreshToken != "" {
        if refreshClaims, err := ValidateToken(refreshToken, s.cfg.SecretKey); err == nil {

			log.Printf("LOGOUT - blacklisting refresh token: %s", refreshToken)	
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

func (s *UserService) GetUserByID(ctx context.Context, id int64) (*model.User, error) {
	return s.repo.GetUserByID(ctx, id)
}

func (s *UserService) VerifyEmail(ctx context.Context, token string) error {
	claims, err := ValidateToken(token, s.cfg.SecretKey)

	if err != nil {
		return err
	}

	if claims.TokenType != "email_verification" {
		return fmt.Errorf("invalid token type")
	}

	return s.repo.MarkUserVerified(ctx, claims.UserID)
}

func (s *UserService) ForgotPassword(ctx context.Context, email string) error {
	user, err := s.repo.GetUserByEmail(ctx, email)

	if err != nil {
		return nil
	}

	resetToken, err := GenerateToken(user.ID, s.cfg.SecretKey, 15 * time.Minute, "password_reset")

	if err != nil {
		log.Print("error gernerating token: %w", err)
		return nil;
	}

	resetLink := s.cfg.BaseURL + "/reset-password?token=" + resetToken

	log.Printf("PASSWORD RESET LINK for %s: %s", email, resetLink)

	return nil
}

func (s * UserService) ResetPassword (ctx context.Context, tokenString string, newPassword string) error {
	claims, err := ValidateToken(tokenString, s.cfg.SecretKey)

	if err != nil {
		return fmt.Errorf("invalid or expired reset link: %w", err)
	}

	if claims.TokenType != "password_reset" {
		return fmt.Errorf("invalid token type")
	}

	isBlackListed, err := s.IsTokenBlackListed(ctx,tokenString)

	if err != nil {
		return err
	}

	if isBlackListed {
		return fmt.Errorf("token has been revoked")
	}

	newHash, err := HashPassword(newPassword)

	if err != nil {
		return err
	}

	err = s.repo.UpdatePassword(ctx, claims.UserID, newHash)

	if err != nil {
		return err
	}

	if blacklistErr := s.BlacklistToken(ctx, tokenString, claims.ExpiresAt.Time); blacklistErr != nil {
		log.Printf("failed to blacklist used reset token for user %d: %v", claims.UserID, blacklistErr)
	}

	return nil
}