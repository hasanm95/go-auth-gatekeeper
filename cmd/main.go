package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/hasanm95/go-auth-gatekeeper/internal/config"
	"github.com/hasanm95/go-auth-gatekeeper/internal/handler"
	"github.com/hasanm95/go-auth-gatekeeper/internal/repository"
	"github.com/hasanm95/go-auth-gatekeeper/internal/service"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func main(){
	ctx := context.Background()
	cfg, err := config.Load()

	if err != nil {
		log.Fatal(err)
	}

	baseURL := strings.TrimRight(cfg.BaseURL, "/") + "/"

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)

	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	pingCtx, cancel := context.WithTimeout(ctx, 5 * time.Second)
	defer cancel()
	
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		log.Fatalf("database ping failed: %v", err)
	}

	fmt.Print("Database connected \n")

	rdb := redis.NewClient(&redis.Options{
		Addr: cfg.Redis_Addr,
		Password: "",
		DB: 0,
	})
	defer rdb.Close()

	_, err = rdb.Ping(ctx).Result();
	if err != nil {
		log.Fatalf("Could not connect to Redis: %v", err)
	}

	fmt.Println("Successfully connected to Redis!")

	userRepo := repository.NewUserRepository(pool)
	userService := service.NewUserService(userRepo)
	handler := handler.Newhandler(*userService)

	mux := chi.NewRouter()

	mux.Post("/register", handler.Register)
	mux.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Post("/refresh", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Post("/logout", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})


	server := &http.Server{
		Addr: ":" + cfg.Port,
		Handler: mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	fmt.Printf("Connecting server on port: %s\n", cfg.Port)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("couldn't connect server: %v", err)
	}

	fmt.Printf("Application is running on: %s\n", baseURL)
}