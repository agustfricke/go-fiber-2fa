package routes

import (
	"github.com/agustfricke/go-fiber-2fa/handlers"
	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(app *fiber.App) {
  app.Post("/signup", handlers.SignUp)
  app.Post("/signin", handlers.SignIn)
  app.Post("/logout", handlers.Logout)
  app.Post("/generate", handlers.GenerateOTP)
  app.Post("/verify", handlers.VerifyOTP)
  app.Post("/disable", handlers.DisableOTP)
}
