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
  
  if user.Otp_enabled == true {
    if payload.Recovery_code == "" {
      valid := totp.Validate(payload.Token, user.Otp_secret)
      if !valid {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
          "status":  "fail",
          "message": "Token 2FA not valid",
        })
      }     
    } else {
        err := bcrypt.CompareHashAndPassword([]byte(user.Revovery_code), []byte(payload.Recovery_code))
        if err != nil {
          return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "fail", "message": "Invalid revovery code"})
        }
    }
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

func GetCodes(c *fiber.Ctx) error {
  db := database.DB
  var users []models.User
  db.Find(&users)
  return c.JSON(users)
}

func GenerateOTP(c *fiber.Ctx) error {
	  tokenUser := c.Locals("user").(*models.User)

    key, err := totp.Generate(totp.GenerateOpts{
        Issuer:      "Tech con Agust",
        AccountName: tokenUser.Email,
        SecretSize:  15,
    })

    if err != nil {
        panic(err)
    }

    var user models.User
    db := database.DB
    result := db.First(&user, "id = ?", tokenUser.ID)
    if result.Error != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "status":  "fail",
            "message": "Correo electrónico o contraseña no válidos",
        })
    }

    hashedOtpSecret, err := bcrypt.GenerateFromPassword([]byte(key.Secret()), bcrypt.DefaultCost)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "status":  "error",
            "message": "No se pudo hacer el hash de secret key",
        })
    }

    hashedOtpUrl, err := bcrypt.GenerateFromPassword([]byte(key.URL()), bcrypt.DefaultCost)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "status":  "error",
            "message": "No se pudo hacer el hash de secret key",
        })
    }

    dataToUpdate := models.User{
        Otp_secret:   string(hashedOtpSecret),
        Otp_auth_url: string(hashedOtpUrl),
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
    tokenUser := c.Locals("user").(*models.User)

    if err := c.BodyParser(&payload); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "status":  "fail",
            "message": err.Error(),
        })
    }

    var user models.User
    db := database.DB
    result := db.First(&user, "id = ?", tokenUser.ID)
    if result.Error != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "status":  "fail",
            "message": "El token no es válido o el usuario no existe",
        })
    }

    valid := totp.Validate(payload.Token, user.Otp_secret)
    if !valid {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "status":  "fail",
            "message": "El token no es válido o el usuario no existe",
        })
    }

    recoveryCode, err := config.GenerateRandomString(10)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "status":  "error",
            "message": "No se pudo generar el código de recuperación",
        })
    }

    hashedRecoveryCode, err := bcrypt.GenerateFromPassword([]byte(recoveryCode), bcrypt.DefaultCost)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "status":  "error",
            "message": "No se pudo hacer el hash el código de recuperación",
        })
    }


    dataToUpdate := models.User{
        Otp_enabled:   true,
        Otp_verified:  true,
        Revovery_code: string(hashedRecoveryCode),
    }

    db.Model(&user).Updates(dataToUpdate)

    userResponse := fiber.Map{
        "id":            user.ID,
        "name":          user.Name,
        "email":         user.Email,
        "otp_enabled":   user.Otp_enabled,
        "recovery_code": recoveryCode, 
        "recovery_code_hash": hashedRecoveryCode, 
    }

    return c.JSON(fiber.Map{
        "otp_verified": true,
        "user":         userResponse,
    })
}

func DisableOTP(c *fiber.Ctx) error {
	  tokenUser := c.Locals("user").(*models.User)

    var user models.User
    db := database.DB
    result := db.First(&user, "id = ?", tokenUser.ID)
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
