package handlers

import (
	"fmt"
	"strings"
	"time"

	"github.com/agustfricke/go-fiber-2fa/config"
	"github.com/agustfricke/go-fiber-2fa/database"
	"github.com/agustfricke/go-fiber-2fa/models"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func SignUp(c *fiber.Ctx) error {
	var payload *models.SignUpInput
  db := database.DB

	if err := c.BodyParser(&payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "fail", "message": err.Error()})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)

	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "fail", "message": err.Error()})
	}

	newUser := models.User{
		Name:     payload.Name,
		Email:    strings.ToLower(payload.Email),
		Password: string(hashedPassword),
	}

	result := db.Create(&newUser)

	if result.Error != nil && strings.Contains(result.Error.Error(), "duplicate key value violates unique") {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"status": "fail", "message": "User with that email already exists"})
	} else if result.Error != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"status": "error", "message": "Something bad happened"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"status": "success", "data": fiber.Map{"user": &newUser}})
}

func SignIn(c *fiber.Ctx) error {
	var payload *models.SignInInput
  db := database.DB

	if err := c.BodyParser(&payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "fail", "message": err.Error()})
	}

	var user models.User
	result := db.First(&user, "email = ?", strings.ToLower(payload.Email))
	if result.Error != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "fail", "message": "Invalid email or Password"})
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(payload.Password))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "fail", "message": "Invalid email or Password"})
	}
  
  valid := totp.Validate(payload.Token, user.Otp_secret)
  if !valid {
      return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
          "status":  "fail",
          "message": "Token 2FA not valid",
      })
  }

	tokenByte := jwt.New(jwt.SigningMethodHS256)

	now := time.Now().UTC()
	claims := tokenByte.Claims.(jwt.MapClaims)
  expDuration := time.Hour * 24

  claims["sub"] = user.ID
  claims["exp"] = now.Add(expDuration).Unix()
  claims["iat"] = now.Unix()
  claims["nbf"] = now.Unix()

	tokenString, err := tokenByte.SignedString([]byte(config.Config("SECRET_KEY")))

	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"status": "fail", "message": fmt.Sprintf("generating JWT Token failed: %v", err)})
	}

	c.Cookie(&fiber.Cookie{
		Name:     "token",
		Value:    tokenString,
		Path:     "/",
		MaxAge:   60 * 60,
		Secure:   false,
		HTTPOnly: true,
		Domain:   "localhost",
	})

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success", "token": tokenString})
}

func Logout(c *fiber.Ctx) error {
	expired := time.Now().Add(-time.Hour * 24)
	c.Cookie(&fiber.Cookie{
		Name:    "token",
		Value:   "",
		Expires: expired,
	})
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success"})
}

func GenerateOTP(c *fiber.Ctx) error {
    var payload *models.OTPInput

    if err := c.BodyParser(&payload); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "status":  "fail",
            "message": err.Error(),
        })
    }

    key, err := totp.Generate(totp.GenerateOpts{
        Issuer:      "Tech con Agust",
        AccountName: payload.Email,
        SecretSize:  15,
    })

    if err != nil {
        panic(err)
    }

    var user models.User
    db := database.DB
    result := db.First(&user, "id = ?", payload.UserId)
    if result.Error != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "status":  "fail",
            "message": "Correo electrónico o contraseña no válidos",
        })
    }

    dataToUpdate := models.User{
        Otp_secret:   key.Secret(),
        Otp_auth_url: key.URL(),
    }

    db.Model(&user).Updates(dataToUpdate)

    otpResponse := fiber.Map{
        "base32":      key.Secret(),
        "otpauth_url": key.URL(),
    }

    return c.JSON(otpResponse)
}

func VerifyOTP(c *fiber.Ctx) error {
    var payload *models.OTPInput

    if err := c.BodyParser(&payload); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "status":  "fail",
            "message": err.Error(),
        })
    }

    message := "El token no es válido o el usuario no existe"

    var user models.User
    db := database.DB
    result := db.First(&user, "id = ?", payload.UserId)
    if result.Error != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "status":  "fail",
            "message": message,
        })
    }

    valid := totp.Validate(payload.Token, user.Otp_secret)
    if !valid {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "status":  "fail",
            "message": message,
        })
    }

    dataToUpdate := models.User{
        Otp_enabled:  true,
        Otp_verified: true,
    }

    db.Model(&user).Updates(dataToUpdate)

    userResponse := fiber.Map{
        "id":          user.ID,
        "name":        user.Name,
        "email":       user.Email,
        "otp_enabled": user.Otp_enabled,
    }

    return c.JSON(fiber.Map{
        "otp_verified": true,
        "user":         userResponse,
    })
}

func DisableOTP(c *fiber.Ctx) error {
    var payload *models.OTPInput

    if err := c.BodyParser(&payload); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "status":  "fail",
            "message": err.Error(),
        })
    }

    var user models.User
    db := database.DB
    result := db.First(&user, "id = ?", payload.UserId)
    if result.Error != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "status":  "fail",
            "message": "El usuario no existe",
        })
    }

    user.Otp_enabled = false
    db.Save(&user)

    userResponse := fiber.Map{
        "id":          user.ID,
        "name":        user.Name,
        "email":       user.Email,
        "otp_enabled": user.Otp_enabled,
    }

    return c.JSON(fiber.Map{
        "otp_disabled": true,
        "user":         userResponse,
    })
}
