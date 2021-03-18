package jwtauth

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
	"time"
)

const salt = "the quick brown fox jumps over a lazy dog"

// Verify the JWT and return claims and errors.
// Response when error occurs.
func AuthAndResponse(w http.ResponseWriter, q *http.Request) (*jwt.StandardClaims, error) {
	tokenString, err := GetTokenString(q)
	if err != nil {
		errorHandler(err.Error(), w, http.StatusUnauthorized)
		return nil, err
	}
	claims, err := ParseToken(tokenString)
	if err != nil {
		errorHandler(err.Error(), w, http.StatusUnauthorized)
		return nil, err
	}
	return claims, nil
}

// Authentication interceptor using net/http.
func HttpMiddleware(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := GetTokenString(r)
		if err != nil {
			errorHandler(err.Error(), w, http.StatusUnauthorized)
			return
		}
		_, err = ParseToken(tokenString)
		if err != nil {
			errorHandler(err.Error(), w, http.StatusUnauthorized)
			return
		}
		return
	}
}

func errorHandler(desc string, w http.ResponseWriter, status int) {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte("{\"message\": \"" + desc + "\"}"))
}

// Authentication middleware using github.com/gin-gonic/gin.
// It also stores claims as key/value pair for this context. You can get it with c.Get("claims")
func GinMiddleware(c *gin.Context) {
	tokenString, err := GetTokenString(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": err.Error()})
		c.Abort()
	}
	claims, err := ParseToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": err.Error()})
		c.Abort()
	}
	c.Set("claims", claims)
	c.Next()
}

// Get token string from HTTP Authorization request header
func GetTokenString(q *http.Request) (string, error) {
	tokenString := q.Header["Authorization"][0]
	if tokenString == "" {
		return "", errors.New("token not found")
	}
	if !strings.HasPrefix(tokenString, "Bearer ") {
		return "", errors.New("token format error")
	}
	tokenString = tokenString[7:]
	if tokenString == "" {
		return "", errors.New("token not found")
	}
	return tokenString, nil
}

// Generate JWT with jwt.StandardClaims.
// IssuedAt and ExpiresAt fields are automatically added.
func GenerateToken(stdClaims jwt.StandardClaims) string {
	stdClaims.IssuedAt = time.Now().Unix()
	stdClaims.ExpiresAt = time.Now().Add(time.Hour * 48).Unix()
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, stdClaims)
	token, _ := claims.SignedString([]byte(salt))
	return token
}

// Parse JWT string and get the claims.
func ParseToken(tokenString string) (*jwt.StandardClaims, error) {
	if tokenString == "" {
		return nil, errors.New("token not found")
	}
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(salt), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*jwt.StandardClaims)
	if ok && token.Valid {
		return claims, nil
	} else {
		return nil, errors.New("token is not valid")
	}
}
