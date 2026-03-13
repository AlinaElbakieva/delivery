package crypto

import (
	"crypto/rsa"
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
}
type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)
const (
	AccessTime  = 15 * time.Minute
	RefreshTime = 7 * 24 * time.Hour
)

func NewJWTService(privateKeyPath, publicKeyPath, issuer string) (*JWTService, error) {
	privData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	pubData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privData)
	if err != nil {
		return nil, err
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pubData)
	if err != nil {
		return nil, err
	}

	return &JWTService{
		privateKey: privKey,
		publicKey:  pubKey,
		issuer:     issuer,
	}, nil
}
func (j *JWTService) GenerateToken(userId uuid.UUID, username, role string, typ TokenType) (string, error) {
	var exp time.Duration
	if typ == AccessToken {
		exp = AccessTime
	} else {
		exp = RefreshTime
	}

	claims := jwt.MapClaims{
		"sub":      userId,
		"username": username,
		"role":     role,
		"typ":      string(typ),
		"iss":      j.issuer,
		"exp":      time.Now().Add(exp).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(j.privateKey)
}

func (j *JWTService) ValidateToken(tokenStr string, expectedType TokenType) (*jwt.Token, jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return j.publicKey, nil
	})
	if err != nil {
		return nil, nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, nil, errors.New("invalid token claims")
	}

	if claims["typ"] != string(expectedType) || claims["iss"] != j.issuer {
		return nil, nil, errors.New("invalid token type or issuer")
	}

	return token, claims, nil
}
