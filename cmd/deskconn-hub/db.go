package main

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Desktops struct{}

func (Desktops) TableName() string {
	return "desktops"
}

type Desktop struct {
	AuthID string `gorm:"column:authid"`
	Realm  string `gorm:"column:realm"`
}

func openDB(databaseURL string) (*gorm.DB, error) {
	return gorm.Open(postgres.Open(databaseURL), &gorm.Config{})
}

func getDesktops(db *gorm.DB) ([]Desktop, error) {
	var desktops []Desktop
	err := db.Model(&Desktops{}).Select("authid", "realm").Find(&desktops).Error
	return desktops, err
}
