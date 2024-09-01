package main

import (
	"math/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
    "golang.org/x/time/rate"
)

var jwtKey = []byte("acac#cc232")

type Credentials struct {
    Email string `json:"email"`
}

type Claims struct {
    Email string `json:"email"`
    jwt.StandardClaims
}
type URLRequest struct {
	URL string `json:"url"`
}

type URLResponse struct {
	ShortUrl string `json:"shortUrl"`
}

// Store for URLs and short codes
var urlStore = make(map[string]string)
var mutex = &sync.Mutex{} 
var rateLimiter = make(map[string]*rate.Limiter)
var rateLimiterMutex sync.Mutex

func getRateLimiter(ip string) *rate.Limiter {
    rateLimiterMutex.Lock()
    defer rateLimiterMutex.Unlock()

    if limiter, exists := rateLimiter[ip]; exists {
        return limiter
    }

    limiter := rate.NewLimiter(1, 5) // 1 request per second with a burst of 5
    rateLimiter[ip] = limiter

    return limiter
}

func rateLimitMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ip := r.RemoteAddr
        limiter := getRateLimiter(ip)

        if !limiter.Allow() {
            http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
            return
        }

        next.ServeHTTP(w, r)
    })
}
func middlewareToken(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        tokenString := r.Header.Get("Authorization")
        if tokenString == "" {
            http.Error(w, "Authorization header missing", http.StatusUnauthorized)
            return
        }

        claims := &Claims{}
        token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
            return jwtKey, nil
        })

        if err != nil || !token.Valid {
            http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
            return
        }

        next.ServeHTTP(w, r)
    })
}
func loginHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Println("Login request received")
    var creds Credentials
    err := json.NewDecoder(r.Body).Decode(&creds)
    if err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }
    fmt.Println("Email", creds.Email)
    expirationTime := time.Now().Add(5 * time.Minute)
    claims := &Claims{
        Email: creds.Email,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: expirationTime.Unix(),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtKey)
    if err != nil {
        http.Error(w, "Error generating token", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func validateTokenHandler(w http.ResponseWriter, r *http.Request) {
    tokenString := r.Header.Get("Authorization")
    if tokenString == "" {
        http.Error(w, "Authorization header missing", http.StatusUnauthorized)
        return
    }

    claims := &Claims{}
    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })

    if err != nil {
        if err == jwt.ErrSignatureInvalid {
            http.Error(w, "Invalid token signature", http.StatusUnauthorized)
            return
        }
        http.Error(w, "Error parsing token", http.StatusBadRequest)
        return
    }

    if !token.Valid {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    w.Write([]byte("Token is valid!"))
}
func shortenURLHandler(w http.ResponseWriter, r *http.Request) {
	var req URLRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Generate a unique short code
	shortCode := generateShortCode()

	// Store the original URL with the short code
	mutex.Lock()
	urlStore[shortCode] = req.URL
	mutex.Unlock()

	shortUrl := fmt.Sprintf("http://localhost:8080/%s", shortCode)
	response := URLResponse{ShortUrl: shortUrl}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the short code from the URL
	vars := mux.Vars(r)
	shortCode := vars["shortCode"]

	// Lookup the original URL
	mutex.Lock()
	originalURL, exists := urlStore[shortCode]
	mutex.Unlock()

	if !exists {
		http.Error(w, "URL not found", http.StatusNotFound)
		return
	}

	// Redirect to the original URL
	http.Redirect(w, r, originalURL, http.StatusMovedPermanently)
}

func generateShortCode() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 6)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}


func main() {
    r := mux.NewRouter()
    r.Use(rateLimitMiddleware)
    // Routes
    r.HandleFunc("/login", loginHandler).Methods("POST")
    r.HandleFunc("/validate", validateTokenHandler).Methods("GET")
    r.Handle("/shorten", middlewareToken(http.HandlerFunc(shortenURLHandler))).Methods("POST")

	// Route to handle redirection based on short code
	r.HandleFunc("/{shortCode}", redirectHandler).Methods("GET")

    // Enable CORS for all routes
    corsHandler := handlers.CORS(
        handlers.AllowedOrigins([]string{"http://localhost:5173"}), // Allow your React frontend origin
        handlers.AllowedMethods([]string{"GET", "POST", "OPTIONS"}),
        handlers.AllowedHeaders([]string{"Authorization", "Content-Type"}),
    )(r)
    fmt.Println("Server running on port 8080")
    // Start server with CORS-enabled router
    http.ListenAndServe(":8080", corsHandler)
}
