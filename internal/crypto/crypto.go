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

type AuthClaims struct {
	jwt.RegisteredClaims
	Username string    `json:"username"`
	Role     string    `json:"role"`
	Typ      TokenType `json:"typ"`
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

	now := time.Now()
	claims := &AuthClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userId.String(),
			Issuer:    j.issuer,
			ExpiresAt: jwt.NewNumericDate(now.Add(exp)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		Username: username,
		Role:     role,
		Typ:      typ,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(j.privateKey)
}

func (j *JWTService) ValidateToken(tokenStr string, expectedType TokenType) (*AuthClaims, error) {
	claims := &AuthClaims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return j.publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	if claims.RegisteredClaims.Issuer != j.issuer {
		return nil, errors.New("invalid token issuer")
	}

	if claims.Typ != expectedType {
		return nil, errors.New("invalid token type")
	}

	return claims, nil
}
