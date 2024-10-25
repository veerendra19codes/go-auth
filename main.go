package main

import (
	"github.com/gin-gonic/gin"
	"github.com/veerendra19codes/jwt-auth/controllers"
	"github.com/veerendra19codes/jwt-auth/initializers"
	"github.com/veerendra19codes/jwt-auth/middleware"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDatabase()
}

func main() {
	r := gin.Default()

	r.POST("/signup", controllers.SignUp)
	r.POST("/login", controllers.Login)
	r.POST("/validate", middleware.RequireAuth, controllers.Validate)

	r.Run()
}
