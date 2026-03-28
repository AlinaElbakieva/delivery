package config

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"time"

	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

type Config struct {
	Port          string
	JWTPrivateKey string
	JWTPublicKey  string
	JWTIssuer     string
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
	ConfigDB      ConfigDB
}

type ConfigDB struct {
	DBUser     string
	DBPassword string
	DBHost     string
	DBPort     string
	DBName     string
}

func LoadConfig() (*Config, error) {
	cfg := &Config{}
	port := os.Getenv("API_PORT")
	if port == "" {
		port = "8080"
	}
	cfg.Port = port

	cfg.JWTPrivateKey = os.Getenv("JWT_PRIVATE_KEY")
	if cfg.JWTPrivateKey == "" {
		cfg.JWTPrivateKey = "private.pem"
	}

	cfg.JWTPublicKey = os.Getenv("JWT_PUBLIC_KEY")
	if cfg.JWTPublicKey == "" {
		cfg.JWTPublicKey = "public.pem"
	}

	issuer := os.Getenv("JWT_ISSUER")
	if issuer == "" {
		issuer = "auth-service"
	}
	cfg.JWTIssuer = issuer

	accessTTLStr := os.Getenv("ACCESS_TTL_MINUTES")
	accessTTL := 15
	if accessTTLStr != "" {
		if v, err := strconv.Atoi(accessTTLStr); err == nil {
			accessTTL = v
		}
	}
	cfg.AccessTTL = time.Duration(accessTTL) * time.Minute

	refreshTTLStr := os.Getenv("REFRESH_TTL_HOURS")
	refreshTTL := 24 * 7
	if refreshTTLStr != "" {
		if v, err := strconv.Atoi(refreshTTLStr); err == nil {
			refreshTTL = v
		}
	}
	cfg.RefreshTTL = time.Duration(refreshTTL) * time.Hour

	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	cfg.ConfigDB = ConfigDB{
		DBUser:     dbUser,
		DBPassword: dbPassword,
		DBHost:     dbHost,
		DBPort:     dbPort,
		DBName:     dbName,
	}

	return cfg, nil
}

func (cfg ConfigDB) ConnectDB() *sql.DB {
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		cfg.DBUser,
		cfg.DBPassword,
		cfg.DBHost,
		cfg.DBPort,
		cfg.DBName,
	)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		logger.Error("failed to open DB: %v", zap.Error(err))
		return nil
	}

	if err := db.Ping(); err != nil {
		logger.Error("failed to ping DB: %v", zap.Error(err))
		return nil
	}

	logger.Info("Connected to Postgres")

	return db
}
