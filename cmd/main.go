package main

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/nurmeden/authentication_service/config"
	"github.com/nurmeden/authentication_service/internal/handler"
	"github.com/nurmeden/authentication_service/internal/repository"
	"github.com/nurmeden/authentication_service/internal/service"
	"github.com/nurmeden/authentication_service/pkg/db/mongo"
	"log"
)

func main() {
	cfg := config.NewConfig()

	ctx := context.TODO()
	client, err := db.LoadDatabase(cfg.MongoDBURI)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	defer client.Disconnect(ctx)

	tokenRepo := repository.NewTokenRepository(client.Database("authentication").Collection("refresh_tokens"))

	authService := service.NewAuthService(tokenRepo)

	handler := handlers.NewApp(authService)

	router := gin.Default()

	router.GET("/token/:userID", handler.TokenHandler)
	router.POST("/refresh", handler.RefreshHandler)

	log.Println("Server is running on port 8080")
	log.Fatal(router.Run(":8080"))
}
