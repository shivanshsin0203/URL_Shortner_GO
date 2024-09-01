package main

import (
    "encoding/json"
    "net/http"
    "time"

    "github.com/golang-jwt/jwt/v4"
    "github.com/gorilla/handlers"
    "github.com/gorilla/mux"
)

var jwtKey = []byte("acac#cc232")

type Credentials struct {
    Email string `json:"email"`
}

type Claims struct {
    Email string `json:"email"`
    jwt.StandardClaims
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    var creds Credentials
    err := json.NewDecoder(r.Body).Decode(&creds)
    if err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

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

func main() {
    r := mux.NewRouter()

    // Routes
    r.HandleFunc("/login", loginHandler).Methods("POST")
    r.HandleFunc("/validate", validateTokenHandler).Methods("GET")

    // Enable CORS for all routes
    corsHandler := handlers.CORS(
        handlers.AllowedOrigins([]string{"http://localhost:5173"}), // Allow your React frontend origin
        handlers.AllowedMethods([]string{"GET", "POST", "OPTIONS"}),
        handlers.AllowedHeaders([]string{"Authorization", "Content-Type"}),
    )(r)

    // Start server with CORS-enabled router
    http.ListenAndServe(":8080", corsHandler)
}
