// @title My Expenses Users API
// @version 1.0
// @description API for managing users in My Expenses app
// @BasePath /api

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
	_ "main/docs"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/swaggo/http-swagger"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/lib/pq"
)

var secretKey = []byte(os.Getenv("JWT_SECRET_KEY"))

type User struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type UserPayload struct {
	User
	Password string `json:"password"`
}

type LoginResponse struct {
	User  `json:"user"`
	Token string `json:"token"`
}

type UserDB struct {
	User
	PwHash string `json:"pwhash"`
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func createToken(email string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"email": email,
			"exp":   time.Now().Add(time.Minute * 10).Unix(),
		})

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func verifyToken(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		return err
	}

	if !token.Valid {
		return fmt.Errorf("invalid token")
	}

	return nil
}

func main() {
	//connect to database
	db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	//create the table if it doesn't exist
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, name TEXT, email TEXT UNIQUE, pwhash TEXT)")

	if err != nil {
		log.Fatal(err)
	}

	//create router
	router := mux.NewRouter()
	router.HandleFunc("/api/users", getUsers(db)).Methods("GET")
	router.HandleFunc("/api/users/{id}", getUser(db)).Methods("GET")
	router.HandleFunc("/api/users", createUser(db)).Methods("POST")
	router.HandleFunc("/api/users/login", logIn(db)).Methods("POST")
	router.HandleFunc("/api/users/{id}", updateUser(db)).Methods("PUT")
	router.HandleFunc("/api/users/{id}", deleteUser(db)).Methods("DELETE")

	// Serve Swagger docs at /docs
	router.PathPrefix("/docs/").Handler(httpSwagger.WrapHandler)

	//start server
	log.Print("listening...")
	log.Fatal(http.ListenAndServe(":8080", corsMiddleware(jsonContentTypeMiddleware(router))))
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", os.Getenv("ALLOWED_ORIGINS"))
		if r.Method == "OPTIONS" {
			log.Println("preflight", r.Method)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, Accept")
			w.Header().Set("Content-Type", "application/json")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func jsonContentTypeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

// get all users
// @Summary Get all users
// @Tags users
// @Produce json
// @Success 200 {array} User
// @Router /users [get]
func getUsers(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query("SELECT id, name, email FROM users")
		if err != nil {
			log.Fatal(err)
		}
		defer rows.Close()

		users := []User{}
		for rows.Next() {
			var u User
			if err := rows.Scan(&u.ID, &u.Name, &u.Email); err != nil {
				log.Fatal(err)
			}
			users = append(users, u)
		}
		if err := rows.Err(); err != nil {
			log.Fatal(err)
		}

		json.NewEncoder(w).Encode(users)
	}
}

// get user by id
// @Summary Get user by ID
// @Tags users
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} User
// @Failure 404 {string} string "User not found"
// @Router /users/{id} [get]
func getUser(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		var u UserDB
		err := db.QueryRow("SELECT id, name, email FROM users WHERE id = $1", id).Scan(&u.ID, &u.Name, &u.Email)
		if err != nil {
			log.Printf("user id %v not found: error %v", id, err)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(u.User)
	}
}

// create user
// @Summary Create a new user
// @Tags users
// @Accept json
// @Produce json
// @Param user body UserPayload true "User payload"
// @Success 200 {object} User
// @Failure 400 {string} string "Bad request"
// @Router /users [post]
func createUser(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var up UserPayload
		json.NewDecoder(r.Body).Decode(&up)
		u := UserDB{User: up.User}
		u.PwHash, _ = HashPassword(up.Password)
		log.Printf("pw %v pwHash %v", up.Password, u.PwHash)

		err := db.QueryRow("INSERT INTO users (name, email, pwhash) VALUES ($1, $2, $3) RETURNING id", u.Name, u.Email, u.PwHash).Scan(&u.ID)
		if err != nil {
			log.Fatal(err)
		}

		// w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		json.NewEncoder(w).Encode(u.User)
	}
}

// update user
// @Summary Update an existing user
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Param user body UserPayload true "User payload"
// @Success 200 {object} User
// @Failure 400 {string} string "Bad request"
// @Failure 404 {string} string "User not found"
// @Router /users/{id} [put]
func updateUser(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var up UserPayload
		json.NewDecoder(r.Body).Decode(&up)

		vars := mux.Vars(r)
		id := vars["id"]

		u := UserDB{User: up.User}
		u.PwHash, _ = HashPassword(up.Password)

		_, err := db.Exec("UPDATE users SET name = $1, email = $2 WHERE id = $3", u.Name, u.Email, id)
		if err != nil {
			log.Fatal(err)
		}

		json.NewEncoder(w).Encode(u)
	}
}

// delete user
// @Summary Delete a user
// @Tags users
// @Param id path int true "User ID"
// @Success 200 {string} string "User deleted"
// @Failure 404 {string} string "User not found"
// @Router /users/{id} [delete]
func deleteUser(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		var u UserDB
		err := db.QueryRow("SELECT email FROM users WHERE id = $1", id).Scan(&u.Email)
		if err != nil {
			log.Printf("user id %v not found: error %v", id, err)
			w.WriteHeader(http.StatusNotFound)
			return
		} else {
			log.Printf("deleting user %v not found", u.Email)
			_, err := db.Exec("DELETE FROM users WHERE id = $1", id)
			if err != nil {
				//todo : fix error handling
				w.WriteHeader(http.StatusNotFound)
				return
			}

			json.NewEncoder(w).Encode("User deleted")
		}
	}
}

// log user in
// @Summary Log in a user
// @Tags users
// @Accept json
// @Produce json
// @Param user body UserPayload true "User payload"
// @Success 200 {object} LoginResponse
// @Failure 401 {string} string "Unauthorized"
// @Router /users/login [post]
func logIn(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var up UserPayload
		json.NewDecoder(r.Body).Decode(&up)
		pwHash, _ := HashPassword(up.Password)

		var u UserDB
		err := db.QueryRow("SELECT * FROM users WHERE email = $1", up.Email).Scan(&u.ID, &u.Name, &u.Email, &u.PwHash)
		if err != nil {
			log.Printf("user %v not found", up.Email)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !CheckPasswordHash(up.Password, pwHash) {
			log.Printf("user %v unauthorized", up.Email)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		tokenString, err := createToken(up.Email)
		if err != nil {
			fmt.Errorf("user %v unauthorized; error: %v", up.Email, err)
			w.WriteHeader(http.StatusUnauthorized)
		}
		resp := LoginResponse{User: up.User, Token: tokenString}
		fmt.Printf("user %v authorized\n", up.Email)
		json.NewEncoder(w).Encode(resp)
		return
	}
}