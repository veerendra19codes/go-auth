package initializers

import "github.com/veerendra19codes/jwt-auth/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.GoUser{})
}
