package main

import (
	"context"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

	helper "my_project/delivery_bot/backend/auth-service/internal"
	"my_project/delivery_bot/backend/auth-service/internal/config"
	"my_project/delivery_bot/backend/auth-service/internal/crypto"
	http_delivery "my_project/delivery_bot/backend/auth-service/internal/handler"
	"my_project/delivery_bot/backend/auth-service/internal/repo"
	"my_project/delivery_bot/backend/auth-service/internal/router"
	"my_project/delivery_bot/backend/auth-service/internal/usecase"

	"github.com/labstack/gommon/log"
	"go.uber.org/zap"
)

// todo запись в базу данных

func main() {
	var wg sync.WaitGroup
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Fatal("failed to load config", zap.Error(err))
	}

	jwtSvc, err := crypto.NewJWTService("private.pem", "public.pem", "auth-service")
	if err != nil {
		logger.Fatal("JWT init failed", zap.Error(err))
	}

	db := cfg.ConfigDB.ConnectDB()
	rd := cfg.ConfigRedis.ConnectRedis(context.Background())

	userRepo := repo.NewUserRepo(db)
	otpRepo := repo.NewOTPRepo(rd)

	authUC := usecase.NewAuthUseCase(userRepo, otpRepo, jwtSvc, helper.SendOTPFake, logger)
	authHandler := http_delivery.NewAuthHandler(authUC, logger)

	router := router.NewRouter(
		authHandler,
	)

	httpHandler := router.Setup()

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: httpHandler,
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()

	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Info("Starting API server", zap.String("port", cfg.Port))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server failed", zap.Error(err))
		}
	}()

	<-ctx.Done()
	logger.Info("Shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("Server forced to shutdown", zap.Error(err))
	}

	wg.Wait()
	log.Info("Service stopped")
}
