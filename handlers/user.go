package handlers

import (
	"github.com/agustfricke/go-fiber-2fa/models"
	"github.com/gofiber/fiber/v2"
)

func GetMe(c *fiber.Ctx) error {
	user := c.Locals("user").(*models.User)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
    "status": "success", 
    "data": fiber.Map{"user": user},
  })
}
