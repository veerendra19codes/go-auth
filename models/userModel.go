package models

import "gorm.io/gorm"

type GoUser struct {
	gorm.Model
	Email    string `gorm:"unique"`
	Password string
}
