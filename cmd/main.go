package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log"
	"net/http"
	"time"
)

type Login struct {
	HashPassword string
	JWToken      string
	CSRFToken    string
}

type RequestUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var jwtSecret = []byte("secret")

var users = map[string]Login{}

func main() {
	r := chi.NewRouter()

	r.Post("/register", handleRegister)
	r.Post("/login", handleLogin)
	r.Group(func(r chi.Router) {
		r.Use(authMiddleware)
		r.Post("/private", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("Hello %s", r.Context().Value("username"))))
		})
		r.Post("/logout", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Set-Cookie", "csrf_token=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly=false")
			w.Header().Set("Set-Cookie", "session_token=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly=true")
			username := r.Context().Value("username").(string)
			user, _ := users[username]
			user.CSRFToken = ""
			user.JWToken = ""
			users[username] = user
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("Goodbye %s", r.Context().Value("username"))))
		})
	})

	http.ListenAndServe(":8080", r)

}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	reqUser := RequestUser{}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	err = json.Unmarshal(body, &reqUser)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(reqUser.Password) < 8 && len(reqUser.Username) < 4 {
		w.WriteHeader(http.StatusNotAcceptable)
		w.Write([]byte("Password too short"))
		return
	}

	if _, ok := users[reqUser.Username]; ok {
		w.WriteHeader(http.StatusNotAcceptable)
		w.Write([]byte("User already exists"))
		return
	}

	hashPassword, err := hashPassword(reqUser.Password)

	users[reqUser.Username] = Login{
		HashPassword: hashPassword,
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User created"))

}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	reqUser := RequestUser{}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	err = json.Unmarshal(body, &reqUser)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	user, ok := users[reqUser.Username]
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("User not found"))
		return
	}
	if !checkPasswordHash(reqUser.Password, users[reqUser.Username].HashPassword) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Wrong password"))
		return
	}

	JWToken, err := generateJWToken(reqUser.Username)
	csrfToken := generateCSRFToken(32)
	user.JWToken = JWToken
	user.CSRFToken = csrfToken
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(time.Hour * 24),
		HttpOnly: false,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    JWToken,
		Expires:  time.Now().Add(time.Hour * 24),
		HttpOnly: true,
	})

	users[reqUser.Username] = user

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Hello %s", reqUser.Username)))
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return false
	}
	return true
}

func generateCSRFToken(len int) string {
	bytes := make([]byte, len)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatal("failed to generate CSRF token: ", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqUser := RequestUser{}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		err = json.Unmarshal(body, &reqUser)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		fmt.Println(reqUser.Username)
		user, ok := users[reqUser.Username]
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		cookie, err := r.Cookie("session_token")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		token := cookie.Value

		fmt.Println(token)

		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, err = ValidateToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		csrf := r.Header.Get("X-Csrf-Token")
		fmt.Println(csrf)
		fmt.Println(user.CSRFToken)
		if csrf == "" || csrf != user.CSRFToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "username", reqUser.Username)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type Claims struct {
	Username string
	jwt.RegisteredClaims
}

func generateJWToken(username string) (string, error) {
	claims := Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, err
}
