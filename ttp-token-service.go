package main

import (
	"bufio"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"net/http"

	"log"

	"crypto/ecdsa"
	"crypto/x509"

	"github.com/golang-jwt/jwt"
)

// Create the JWT key used to create the signature
// JTE TODO read this from environment or file or db
//var jwtKey = []byte(("my_secret_key"))

const g_jwtExpiryHours = 12
const g_audience = "certification-pos-v1"
const g_kid = "000-0000-00000"
const g_privateKeyFilename = "private-key.pem"

var g_privatekey *ecdsa.PrivateKey

// const mid = 100
// const mbn = "Acme Sock"
// const mcc = 1000
// const terminalProfileId = "111-1111-11111"

type JWTRequestData struct {
	Mid  string `json:"mid" validate:"required"`
	Mcc  string `json:"mcc" validate:"required"`
	Mbn  string `json:"mbn" validate:"required"`
	Tpid string `json:"tpid" validate:"required"`
}

func loadSigningKey() (*ecdsa.PrivateKey, error) {

	// Open pem file containing private signing key
	privateKeyFile, err := os.Open(g_privateKeyFilename)

	if err != nil {
		return nil, err
	}

	// Load data from file
	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	data, _ := pem.Decode([]byte(pembytes))
	privateKeyFile.Close()

	// Decode data into our ECDSA key
	privateKeyImported, err := x509.ParseECPrivateKey(data.Bytes)
	if err != nil {
		return nil, err
	}
	//fmt.Println("Private Key : ", privateKeyImported)

	return privateKeyImported, nil
}

/*
func getSigningKey() (*ecdsa.PrivateKey, error) {
	// Generate ECDSA private key
	pubkeyCurve := elliptic.P256() //see http://golang.org/pkg/crypto/elliptic/#P256

	privatekey, err := ecdsa.GenerateKey(pubkeyCurve, rand.Reader) // this generates a public & private key pair

	return privatekey, err
}
*/

// Generates a TTP Session token with the specified
func generateJWT(reqData JWTRequestData) (string, error) {

	// Setup our claims
	now := time.Now()

	claims := jwt.MapClaims{}
	claims["aud"] = g_audience
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(time.Hour * g_jwtExpiryHours).Unix()
	claims["jti"] = uuid.NewString()
	claims["tpid"] = reqData.Tpid
	claims["mid"] = reqData.Mid
	claims["mbn"] = reqData.Mbn
	claims["mcc"] = reqData.Mcc

	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Key id must go in JWT header
	token.Header["kid"] = g_kid

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(g_privatekey)

	return tokenString, err
}

// POST /tokens handler
func createToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Declare a new JWTRequestData struct.
	var reqData JWTRequestData

	// Try to decode the request body into the struct. If there is an error,
	// respond to the client with the error message and a 400 status code.
	err := json.NewDecoder(r.Body).Decode(&reqData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//TODO JTE not sure why I have to manually check these, when I marked them required in the struct
	if reqData.Mbn == "" || reqData.Mcc == "" || reqData.Mid == "" || reqData.Tpid == "" {
		http.Error(w, "{'error':'You must provide mbn, mcc, mid, and tpid'}", http.StatusBadRequest)
		return
	}

	tokenString, err := generateJWT(reqData)

	if err == nil {
		w.Write([]byte("{'token':'" + tokenString + "'}"))
		// Implicitly returns status 200
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
}

func main() {

	// Load signing key from file
	var err error
	g_privatekey, err = loadSigningKey()

	if err != nil {
		fmt.Println("Unable to load private key from file")
		panic(err)
	} else {
		fmt.Println("Successfully loaded private key")
	}

	// Init Router
	r := mux.NewRouter()

	// Set routes
	r.HandleFunc("/tokens", createToken).Methods("POST")

	// Start listening and handling token requests
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
		fmt.Printf("defaulting to port %s\n", port)
	}
	fmt.Println("Listening on port", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
