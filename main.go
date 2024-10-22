package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secretKey = []byte("mySecretKey")

func createJWT(username string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Minute * 5).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func validateJWT(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("yanlış imzalama yöntemi")
		}
		return secretKey, nil
	})

	if err != nil {
		return "", err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		username := claims["username"].(string)
		return username, nil
	} else {
		return "", fmt.Errorf("token gecersiz")
	}
}

func main() {
	token, err := createJWT("johndoe")
	if err != nil {
		fmt.Println("hata:", err)
		return
	}
	fmt.Println("olusturulan jwt:", token)

	username, err := validateJWT(token)
	if err != nil {
		fmt.Println("Doğrulama Hatası:", err)
		return
	}

	fmt.Println("Doğrulanan Kullanıcı:", username)

}
