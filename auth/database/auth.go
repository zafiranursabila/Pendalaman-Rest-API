package database

import (
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

type Auth struct {
	ID int `gorm:"primary_key" json:"-"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Role int `json:omitempty`
}
type TokenDetails struct {
	//Berisi akses token
	AccessToken string
	//berisi refresh token
	RefreshToken string
	//waktu expired dari AccessToken
	AtExpires int64
	//waktu expired dari RefreshToken
	RtExpires int64
}

func Validate (token string, db *gorm.DB) (*Auth,error){
	var auth Auth
	//if err := db.Where(&Auth{Token: token}).First(&auth).Error;err != nil{
	//	if err == gorm.ErrRecordNotFound{
	//		return nil,errors.Errorf("invalid token")
	//	}
	//}

	return &auth,nil
}

func (auth *Auth) SignUp (db *gorm.DB) error{
	
	if err := db.Where(&Auth{Username: auth.Username}).First(auth).Error;err != nil{
		if err == gorm.ErrRecordNotFound{
			if err := db.Create(auth).Error;err != nil{
				return err
			}
		}else {
			return err
		}
	}
	
	return nil
}

func (auth *Auth) Login (db *gorm.DB) (*Auth,error){
	if err := db.Where(&Auth{Username: auth.Username, Password: auth.Password}).First(auth).Error;err != nil{
		if err == gorm.ErrRecordNotFound{
			return nil,errors.Errorf("wrong email/password")
		}
	}

	return auth,nil
}
