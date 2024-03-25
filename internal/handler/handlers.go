package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/nurmeden/authentication_service/internal/service"
	"net/http"
)

type Handler interface {
	TokenHandler(c *gin.Context)
	RefreshHandler(c *gin.Context)
}

type handler struct {
	service *service.AuthService
}

func NewApp(authService *service.AuthService) Handler {
	return &handler{
		service: authService,
	}
}

func (a *handler) TokenHandler(c *gin.Context) {
	userID := c.Param("userID")

	tokens, err := a.service.GenerateTokens(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	c.JSON(http.StatusOK, tokens)
}

func (a *handler) RefreshHandler(c *gin.Context) {
	refreshToken := c.PostForm("refresh_token")

	accessToken := c.GetHeader("Authorization")

	if refreshToken == "" || accessToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Access or refresh token is missing"})
		return
	}

	tokens, err := a.service.RefreshTokens(accessToken, refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to refresh tokens"})
		return
	}

	c.JSON(http.StatusOK, tokens)
}
