package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	// "github.com/rs/cors"
	"github.com/urfave/negroni"
)

const (
	privKeyPath = "keys/app.rsa"
	pubKeyPath  = "keys/app.rsa.pub"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
	users     []User
)

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func initKeys() {
	signBytes, err := ioutil.ReadFile(privKeyPath)
	fatal(err)

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	fatal(err)

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	fatal(err)

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	fatal(err)
}

type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Alias    string `json:"alias"`
	Email    string `json:"email"`
	IsAdmin  bool   `json:"isadmin"`
}

type DataAdmin struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Task     string `json:"task"`
	IsOnline bool   `json:"isonline"`
}

type Response struct {
	Data string `json:"data"`
}

type Token struct {
	Token string `json:"token"`
}

func InitUsersData() {
	admin := User{100, "admin", "ngadimin", "admin@gmail.com", false}
	users = append(users, admin)
	juang := User{101, "juang", "juangnakarani", "juang@gmail.com", false}
	users = append(users, juang)
	anu := User{102, "anu", "mrxx", "anu@gmail.com", true}
	users = append(users, anu)
	ani := User{103, "ana", "blackiron", "ani@gmail.com", false}
	users = append(users, ani)
}

func StartServer() {
	// c := cors.New(cors.Options{
	// 	AllowedOrigins: []string{"*"},
	// })

	mux := http.NewServeMux()
	// Non-Protected Endpoint(s)
	// mux.HandleFunc("/login", LoginHandler)
	mux.Handle("/login", negroni.New(
		negroni.HandlerFunc(AllowCORS),
		negroni.Wrap(http.HandlerFunc(LoginHandler)),
	))
	

	// Protected Endpoints
	mux.Handle("/resource", negroni.New(
		negroni.HandlerFunc(ValidateTokenMiddleware),
		negroni.Wrap(http.HandlerFunc(ProtectedHandler)),
	))

	// mux.Handle("/admin", negroni.New(
	// 	negroni.HandlerFunc(AllowCORS),
	// 	negroni.HandlerFunc(ValidateTokenMiddleware),
	// 	negroni.Wrap(http.HandlerFunc(ProtectedAdminPanel)),
	// ))
	mux.Handle("/admin", negroni.New(
		negroni.HandlerFunc(AllowCORS),
		negroni.HandlerFunc(ValidateTokenMiddleware),
		negroni.Wrap(http.HandlerFunc(ProtectedAdminPanel)),
	))


	mux.HandleFunc("/ngadimin", NgadiminHandler)

	log.Println("Now listening...")

	n := negroni.Classic()
	// n.Use(c)
	n.UseHandler(mux)
	n.Run(":8090")
	//http.ListenAndServe(":8090", c.Handler())

}

func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		// w.Header().Set("Access-Control-Allow-Headers",
		// 	"Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		w.Header().Set("Content-Type", "application/json")
		// w.Header().Set("Access-Control-Allow-Methods", "POST")
	}
	response := Response{"Gained access to protected resource"}
	JsonResponse(response, w)

}

func ProtectedAdminPanel(w http.ResponseWriter, r *http.Request) {
	// w.Header().Set("Access-Control-Allow-Methods", "POST")
		response := Response{"Welcome to admin page.."}
		JsonResponse(response, w)
}

// test Access-Control-Allow-Origin
func NgadiminHandler(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" {
		log.Println("test print origin->", origin)
		w.Header().Set("Access-Control-Allow-Origin", origin)
		// w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	response := Response{"Welcome to ngadimin page.."}
	JsonResponse(response, w)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// if r.Method == "POST" {
		fmt.Println("yuk login...")
		var user UserCredentials
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:8080")
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Error in request")
			return
		}
		fmt.Println("yuk username password ...")
		var usr = user.Username
		var passwd = user.Password

		fmt.Println("json username:", usr)
		fmt.Println("json password:", passwd)

		fmt.Println("compare username: ", strings.Compare(usr, "admin"))
		fmt.Println("compare password: ", strings.Compare(passwd, "admin"))

		if strings.ToLower(usr) == "admin" {
			if passwd == "admin" {
				var userdata User
				for _, userx := range users {
					if userx.Username == user.Username {
						userdata = userx
					}
				}
				token := jwt.New(jwt.SigningMethodRS256)
				claims := make(jwt.MapClaims)
				claims["exp"] = time.Now().Add(time.Hour * time.Duration(1)).Unix()
				claims["iat"] = time.Now().Unix()
				claims["userdata"] = userdata
				token.Claims = claims
		
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprintln(w, "Error extracting the key")
					fatal(err)
				}
		
				tokenString, err := token.SignedString(signKey)
		
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprintln(w, "Error while signing the token")
					fatal(err)
				}
		
				response := Token{tokenString}
				JsonResponse(response, w)
			}else{
				w.WriteHeader(http.StatusForbidden)
				fmt.Println("Error logging in")
				fmt.Fprint(w, "Invalid credentials")
				return
			}
		}else{
			w.WriteHeader(http.StatusForbidden)
			fmt.Println("Error logging in")
			fmt.Fprint(w, "Invalid credentials")
			return
		}
	
	// }else {
	// 	w.WriteHeader(http.StatusMethodNotAllowed)
	// }

}

func AllowCORS(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	fmt.Println("setting CORS...")
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "POST")
	}

	// handle preflight request
	if r.Method == "OPTIONS" {
		// r.Header.Get("Access-Control-Request-Method") could be PUT, DELETE
		// but we needs to return what we actually supports to enable browser cache the preflight
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, OPTIONS")
		w.Header().Set(
			"Access-Control-Allow-Headers",
			"Accept, Content-Type, Content-Length, Accept-Encoding, Authorization",
		)
		w.WriteHeader(http.StatusAccepted)
		// return
	}
	next(w, r)
}

func ValidateTokenMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	fmt.Println("checking token...")
	token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor,
		func(token *jwt.Token) (interface{}, error) {
			return verifyKey, nil
		})

	if err == nil {
		if token.Valid {
			fmt.Println("token valid...")
			// test claim token
			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				fmt.Println("test claim- ", claims["userdata"], " -end test claim")
			} else {
				fmt.Println(err)
			}
			// w.WriteHeader(http.StatusOK)
			w.WriteHeader(http.StatusAccepted)
			next(w, r)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Token is not valid")
			return
		}
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Println("ini err != nil")
		fmt.Fprint(w, "Unauthorized access to this resource")
		return
	}
}

func JsonResponse(response interface{}, w http.ResponseWriter) {

	json, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}

func main() {
	InitUsersData()
	initKeys()
	StartServer()
}
