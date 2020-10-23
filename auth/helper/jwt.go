package helper

import (
	"fmt"
	"log"
	"net/http"
	_ "strconv"
	"strings"
	"time"

	"github.com/FadhlanHawali/Digitalent-Kominfo_Pendalaman-Rest-API/auth/constant"
	"github.com/FadhlanHawali/Digitalent-Kominfo_Pendalaman-Rest-API/auth/database"
	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

func CreateToken(role int, IdUser string) (error, *database.TokenDetails) {
	var rolestr string

	if role == constant.ADMIN {
		rolestr = "admin"
	} else if role == constant.CONSUMER {
		rolestr = "consumer"
	}

	//token details initialization
	td := &database.TokenDetails{}
	//Set waktu access token expiry
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	//set waktu refresh token expiry
	td.RtExpires = time.Now().Add(time.Hour).Unix()

	//
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id_user": idUser,
		"role":    role,
		"exp":     td.RtExpress,
	})

	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id_user": IdUser,
		"role":    role,
		"exp":     td.RtExpires,
	})

	td.RefreshToken, err = rt.SignedString([]byte(fmt.Sprintf("refresh_secret_%s_digitalent", roleStr)))
	if err != nil {
		return err, &database.TokenDetails{}
	}

	return nil, td
}

func ExtractToken(roles int, r *http.Request) string {
	var bearToken string

	if roles == constant.ADMIN {
		bearToken = r.Header.Get("digitalent-admin")
	} else if roles == constant.CONSUMER {
		bearToken = r.Header.Get("digitalent-consumer")
	}
	//normally Authorization the_token_xxx
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func VerifyToken(r *http.Request) (*jwt.Token, error) {
	var roleStr string
	var roles int
	if r.Header.Get("digitalent-admin") != "" {
		roleStr = "admin"
		roles = constant.ADMIN
	} else if r.Header.Get("digitalent-consumer") != "" {
		roleStr = "consumer"
		roles = constant.CONSUMER
	} else {
		return nil, errors.Errorf("Session Invalid")
	}

	tokenString := ExtractToken(roles, r)
	log.Println(tokenString)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if jwt.GetSigningMethod("HS256") != token.Method {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		//TODO SET IN ENV
		return []byte(fmt.Sprintf("secret_%s_digitalent", roleStr)), nil
	})

	if err != nil {
		return nil, err
	}
	return token, nil
}

func TokenValid(r *http.Request) (string, int, error) {
	token, err := VerifyToken(r)
	if err != nil {
		return "", 0, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		idUser, ok := claims["id_user"].(string)
		role, ok := claims["role"]
		if !ok {
			return "", 0, err
		}
		log.Println("ROLER : ", role)
		return idUser, int(role.(float64)), nil
	}

	return "", 0, err
}
