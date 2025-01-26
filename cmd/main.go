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
	"sync"
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

var users = make(map[string]*Login)
var mu sync.RWMutex

func main() {
	r := chi.NewRouter()

	r.Post("/register", handleRegister)
	r.Post("/login", handleLogin)
	r.Group(func(r chi.Router) {
		r.Use(authMiddleware)
		r.Post("/private", handlePrivate)
		r.Post("/logout", handleLogout)
	})

	fmt.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func handlePrivate(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Hello %s", username)))
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	reqUser := RequestUser{}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	err = json.Unmarshal(body, &reqUser)
	if err != nil || len(reqUser.Password) < 8 || len(reqUser.Username) < 4 {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()
	if _, ok := users[reqUser.Username]; ok {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	hashPassword, err := hashPassword(reqUser.Password)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	users[reqUser.Username] = &Login{HashPassword: hashPassword}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User created"))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	reqUser := RequestUser{}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	err = json.Unmarshal(body, &reqUser)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	mu.RLock()
	user, ok := users[reqUser.Username]
	mu.RUnlock()
	if !ok || !checkPasswordHash(reqUser.Password, user.HashPassword) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	JWToken, err := generateJWToken(reqUser.Username)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}
	csrfToken := generateCSRFToken(32)

	user.JWToken = JWToken
	user.CSRFToken = csrfToken

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false,
		MaxAge:   86400,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    JWToken,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400,
	})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Hello %s", reqUser.Username)))
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)

	mu.Lock()
	defer mu.Unlock()

	user, exists := users[username]
	if exists {
		user.CSRFToken = ""
		user.JWToken = ""
	}

	w.Header().Set("Set-Cookie", "csrf_token=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly=false")
	w.Header().Set("Set-Cookie", "session_token=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly=true")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Goodbye %s", username)))
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
	return err == nil
}

func generateCSRFToken(len int) string {
	bytes := make([]byte, len)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatal("failed to generate CSRF token:", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil || cookie.Value == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		claims, err := ValidateToken(cookie.Value)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		csrf := r.Header.Get("X-Csrf-Token")
		mu.RLock()
		user, ok := users[claims.Username]
		mu.RUnlock()

		if !ok || csrf == "" || csrf != user.CSRFToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "username", claims.Username)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type Claims struct {
	Username string `json:"username"`
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
