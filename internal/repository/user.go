package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/hasanm95/go-auth-gatekeeper/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type pgUserRepository struct {
	db *pgxpool.Pool
}

func NewUserRepository (db *pgxpool.Pool) model.UserRepository {
	return &pgUserRepository {
		db: db,
	}
}

func (r *pgUserRepository) CreateUser (ctx context.Context, email string, passwordHash string) (*model.User, error) {
	query := `INSERT INTO users (email, password_hash) VALUES($1, $2) RETURNING id, email, password_hash, created_at, is_verified`

	user := &model.User{}

	err := r.db.QueryRow(ctx, query, email, passwordHash).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.CreatedAt,
		&user.IsVerified,
	)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return nil, fmt.Errorf("postgres error: Code %s, Message: %s", pgErr.Code, pgErr.Message)
		}

		// 2. Check for the missing row error
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("insert ran but zero rows were returned. Check for triggers or ON CONFLICT rules")
		}

		return nil, err
	}

	return user, nil
}

func (r *pgUserRepository) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	query := `SELECT id, email, password_hash, created_at, is_verified FROM users WHERE email = $1`

	row := r.db.QueryRow(ctx, query, email)

	var user model.User

	if err := row.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.IsVerified); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, model.ErrUserNotFound
		}
		return nil, fmt.Errorf("querying user by email: %w", err)
	}

	return &user, nil
} 

func (r *pgUserRepository) GetUserByID(ctx context.Context, id int64) (*model.User, error){
	query := `SELECT id, email, password_hash, created_at, is_verified FROM users WHERE id = $1`

	row := r.db.QueryRow(ctx, query, id)

	user := &model.User{}

	if err := row.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.IsVerified); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, model.ErrUserNotFound
		}
		return nil, fmt.Errorf("querying user by id: %w", err)
	}

	fmt.Printf("DEBUG REPO: User ID %d, IsVerified in DB scan is: %t\n", user.ID, user.IsVerified)

	return user, nil
}

func (r *pgUserRepository) MarkUserVerified(ctx context.Context, userID int64) error {
	query := `UPDATE users SET is_verified = true WHERE id = $1`

	commandTag, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("updating is verified: %w", err)
	}

	if commandTag.RowsAffected() == 0 {
		return fmt.Errorf("user with ID %d not found", userID) 
	}

	return nil
}
