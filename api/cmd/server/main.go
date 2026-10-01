package main

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/izagoto/cybersecurity-lab/internal/auth"
	"github.com/izagoto/cybersecurity-lab/internal/auth/token"
	"github.com/izagoto/cybersecurity-lab/internal/user"
)

func main() {
	router := gin.Default()

	userStore := user.NewStore()
	tokenService := token.NewService(
		"local-development-secret",
	)

	authHandler := auth.NewHandler(
		userStore,
		tokenService,
	)

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	api := router.Group("/api")
	{
		authRoutes := api.Group("/auth")
		{
			authRoutes.POST("/register", authHandler.Register)
			authRoutes.POST("/login", authHandler.Login)
		}
	}

	router.Run(":8080")
}
