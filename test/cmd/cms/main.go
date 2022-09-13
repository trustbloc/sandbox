/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

const (
	servePortEnvKey = "SERVE_PORT"
)

func main() {
	port := os.Getenv(servePortEnvKey)
	if port == "" {
		panic("port to be served not provided")
	}

	router := mux.NewRouter()

	router.HandleFunc("/", admin).Methods(http.MethodGet)
	router.HandleFunc("/admin", admin).Methods(http.MethodGet)
	router.HandleFunc("/admin/auth/local", adminRegister).Methods(http.MethodPost)
	router.HandleFunc("/admin/auth/local/register", adminRegister).Methods(http.MethodPost)
	router.HandleFunc("/users", getUsers).Methods(http.MethodGet)
	router.HandleFunc("/{collection}", getCollectionData)

	fmt.Println("server starting at " + port)
	fmt.Println(http.ListenAndServe(":"+port, router))
}

func admin(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func adminRegister(w http.ResponseWriter, r *http.Request) {
	sendResponse(w, http.StatusOK, &struct {
		JWT string `json:"jwt"`
	}{
		JWT: uuid.NewString(),
	})
}

func getCollectionData(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	coll := vars["collection"]

	testData, err := ioutil.ReadFile(filepath.Clean("./testdata/" + coll + ".json"))
	if err != nil {
		fmt.Printf("failed to read test files  %s", err.Error())
		return
	}

	var data interface{}

	err = json.Unmarshal(testData, &data)
	if err != nil {
		fmt.Printf("json marshal error , %s", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_, err = w.Write(json.RawMessage(testData))
	if err != nil {
		fmt.Printf("failed to write the collection data , %s", err.Error())
	}
}

func sendResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.WriteHeader(statusCode)

	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		handleError(w, http.StatusInternalServerError,
			fmt.Sprintf("unable to send success response, %s", err.Error()))
	}
}

func handleError(w http.ResponseWriter, statusCode int, msg string) {
	w.WriteHeader(statusCode)

	err := json.NewEncoder(w).Encode(ErrorResponse{
		Message: msg,
	})

	if err != nil {
		log.Fatalf("Unable to send error message, %s", err)
	}
}

// ErrorResponse to send error message in the response.
type ErrorResponse struct {
	Message string `json:"errMessage,omitempty"`
}

type cmsUser struct {
	UserID string `json:"userid"`
	Name   string `json:"name"`
	Email  string `json:"email"`
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	u := []cmsUser{{
		UserID: "strapi",
		Name:   "strapi",
		Email:  "user@strapi.io",
	}}

	sendResponse(w, http.StatusOK, u)
}
