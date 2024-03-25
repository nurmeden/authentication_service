package service

import (
	"encoding/base64"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/nurmeden/authentication_service/internal/repository"
	"github.com/nurmeden/authentication_service/pkg/utils"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"time"
)

const tokenLifeTime = 15
const defaultKey = "default-token-secret-key"

var (
	accessTokenSecretKey  = []byte(utils.GetEnv("ACCESS_TOKEN_SECRET_KEY", defaultKey))
	refreshTokenSecretKey = []byte(utils.GetEnv("REFRESH_TOKEN_SECRET_KEY", defaultKey))
)

type AuthService struct {
	repository repository.TokenRepository
}

func NewAuthService(tokenRepo repository.TokenRepository) *AuthService {
	return &AuthService{
		repository: tokenRepo,
	}
}

type JWTData struct {
	jwt.StandardClaims
	CustomClaims map[string]string `json:"custom_claims"`
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (a *AuthService) GenerateTokens(userID string) (*Tokens, error) {
	accessToken, err := generateAccessToken(userID)
	if err != nil {
		return nil, err
	}

	refreshToken, err := generateRefreshToken()
	if err != nil {
		return nil, err
	}

	err = a.repository.SaveRefreshToken(userID, refreshToken)
	if err != nil {
		return nil, err
	}

	return &Tokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (a *AuthService) RefreshTokens(accessToken, refreshToken string) (*Tokens, error) {
	userID, err := a.validateRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	_, err = jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return accessTokenSecretKey, nil
	})

	if err != nil {
		return nil, errors.New("invalid access token")
	}

	newAccessToken, err := generateAccessToken(userID)
	if err != nil {
		return nil, err
	}

	newRefreshToken, err := generateRefreshToken()
	if err != nil {
		return nil, err
	}

	err = a.repository.SaveRefreshToken(userID, newRefreshToken)
	if err != nil {
		return nil, err
	}

	return &Tokens{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func generateAccessToken(userID string) (string, error) {
	claims := JWTData{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Duration(tokenLifeTime)).Unix(),
		},
		CustomClaims: map[string]string{
			"user_id": userID,
			"email":   "nurmeden.02@gmail.com",
		},
	}

	tokenString := jwt.NewWithClaims(jwt.SigningMethodES512, claims)

	token, err := tokenString.SignedString(accessTokenSecretKey)

	return token, err
}

func generateRefreshToken() (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	refreshToken := base64.StdEncoding.EncodeToString(token)
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedToken), nil
}

func (a *AuthService) validateRefreshToken(refreshToken string) (string, error) {
	hashedToken, err := a.repository.GetRefreshTokenHash(refreshToken)
	if err != nil {
		return "", err
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(refreshToken))
	if err != nil {
		return "", errors.New("invalid refresh token")
	}

	tokenClaims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(refreshToken, tokenClaims, func(token *jwt.Token) (interface{}, error) {
		return refreshTokenSecretKey, nil
	})
	if err != nil {
		var validateError *jwt.ValidationError
		if errors.As(err, &validateError) {
			if validateError.Errors&jwt.ValidationErrorMalformed != 0 {
				return "", errors.New("token is malformed")
			} else if validateError.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				return "", errors.New("token is either expired or not active yet")
			} else {
				return "", err
			}
		}
		return "", errors.New("invalid refresh token")
	}

	userID, ok := tokenClaims["user_id"].(string)
	if !ok {
		return "", errors.New("invalid refresh token")
	}

	return userID, nil
}
