package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/hasanm95/go-auth-gatekeeper/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
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
		fmt.Printf("database ping failed: %v", err)
	}

	fmt.Print("Database connected \n")

	server := &http.Server{
		Addr: ":" + cfg.Port,
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