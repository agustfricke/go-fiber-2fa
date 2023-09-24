package routes

import (
	"github.com/agustfricke/go-fiber-2fa/handlers"
	"github.com/agustfricke/go-fiber-2fa/middleware"
	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(app *fiber.App) {
  app.Post("/signup", handlers.SignUp)
  app.Post("/signin", handlers.SignIn)
  app.Post("/logout", middleware.DeserializeUser, handlers.Logout)
  app.Post("/generate", middleware.DeserializeUser, handlers.GenerateOTP)
  app.Post("/verify", middleware.DeserializeUser, handlers.VerifyOTP)
  app.Post("/disable", middleware.DeserializeUser, handlers.DisableOTP)
}
