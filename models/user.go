package models

import "gorm.io/gorm"

// Include recovery codes 
type User struct {
  gorm.Model
	Name      string     `gorm:"type:varchar(100);not null"`
	Email     string     `gorm:"type:varchar(100);uniqueIndex;not null"`
	Password  string     `gorm:"type:varchar(100);not null"`
	Otp_enabled  bool    `gorm:"default:false;"`
	Otp_verified bool    `gorm:"default:false;"`
  Revovery_code string `gorm:"type:varchar(100)"`

	Otp_secret   string
	Otp_auth_url string
}

type SignUpInput struct {
	Name            string `json:"name" validate:"required"`
	Email           string `json:"email" validate:"required"`
	Password        string `json:"password" validate:"required,min=8"`
}

type SignInInput struct {
	Email     string `json:"email"  validate:"required"`
	Password  string `json:"password"  validate:"required"`
  Token     string `json:"token"`
  Recovery_code string `json:"recovery_code"`
}

type OTPInput struct {
	Token   string `json:"token"`
}
