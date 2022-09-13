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

//func getCollectionData(w http.ResponseWriter, r *http.Request) {
//	vars := mux.Vars(r)
//	coll := vars["collection"]
//
//	fmt.Println("collection name =", coll)
//
//	data, err := ioutil.ReadFile("./testdata/" + coll + ".json")
//	if err != nil {
//		fmt.Println("File reading error", err)
//		return
//	}
//
//	var data1 Person
//	err = json.Unmarshal(data, &data1)
//	if err != nil {
//		fmt.Println("marshal error", err)
//		return
//	}
//
//	d, err := json.Marshal(data1)
//	if err != nil {
//		fmt.Println("marshal error", err)
//		return
//	}
//
//	w.Header().Set("Content-Type", "application/json")
//	w.WriteHeader(http.StatusOK)
//	w.Write(d)
//	//sendResponse(w, http.StatusOK, data1)
//}

//type Person struct {
//	Userid     string `json:"userid"`
//	Vcmetadata struct {
//		Context     []string `json:"@context"`
//		Name        string   `json:"name"`
//		Description string   `json:"description"`
//	} `json:"vcmetadata"`
//	Vccredentialsubject struct {
//		BirthCountry  string   `json:"birthCountry"`
//		BirthDate     string   `json:"birthDate"`
//		FamilyName    string   `json:"familyName"`
//		Gender        string   `json:"gender"`
//		GivenName     string   `json:"givenName"`
//		ID            string   `json:"id"`
//		Image         string   `json:"image"`
//		LprCategory   string   `json:"lprCategory"`
//		LprNumber     string   `json:"lprNumber"`
//		ResidentSince string   `json:"residentSince"`
//		Type          []string `json:"type"`
//	} `json:"vccredentialsubject"`
//}

func getCollectionData(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	coll := vars["collection"]

	fmt.Println("collection name =", coll)

	data, err := ioutil.ReadFile("./testdata/" + coll + ".json")
	if err != nil {
		fmt.Println("File reading error", err)
		return
	}

	var data1 interface{}
	err = json.Unmarshal(data, &data1)
	if err != nil {
		fmt.Println("marshal error", err)
		return
	}

	fmt.Println("collection data=", string(data))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(json.RawMessage(data))

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
