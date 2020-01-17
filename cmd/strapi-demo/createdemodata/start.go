/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package createdemodata

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	cmdutils "github.com/trustbloc/edge-store/pkg/utils/cmd"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the strapi-demo instance on. Format: HostName:Port."
	hostURLEnvKey        = "STRAPI-DEMO_ADMIN_URL"
	adminURLEndpoint     = "/admin/auth/local/register"
	studentCardsEndpoint = "/studentcards"
	transcriptEndpoint   = "/transcripts"
	post                 = "POST"
	get                  = "GET"

	strapiCodeFile = "./strapi.txt"
)

type strapiDemoParameters struct {
	client   *http.Client
	adminURL string
}
type strapiUser struct {
	Jwt  string `json:"jwt"`
	User user   `json:"user"`
}
type user struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	IsAdmin  bool   `json:"isAdmin"`
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd() *cobra.Command {
	startCmd := createStartCmd()

	createFlags(startCmd)

	return startCmd
}
func createStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create-demo-data",
		Short: "create demo data",
		Long:  "Start populating data in strapi with default studentcards and transcripts",
		RunE: func(cmd *cobra.Command, args []string) error {
			hostURL, err := cmdutils.GetUserSetVar(cmd, hostURLFlagName, hostURLEnvKey, false)
			if err != nil {
				return err
			}
			parameters := &strapiDemoParameters{
				client:   &http.Client{},
				adminURL: hostURL,
			}
			return startStrapiDemo(parameters)
		},
	}
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
}

// For Demo you can verify the records by browsing http://localhost:1337/admin/
func startStrapiDemo(parameters *strapiDemoParameters) error {
	var client = parameters.client

	adminUserValues := map[string]string{
		"username": "strapi",
		"email":    "user@strapi.io",
		"password": "strapi"}

	authToken, err := createAdminUser(client, parameters.adminURL, adminUserValues)
	if err != nil {
		return err
	}
	// dummy data for demo purposes
	studentRecord1 := map[string]interface{}{
		"studentid":  "1234568",
		"name":       "Foo",
		"email":      "foo@bar.com",
		"university": "Faber College",
		"semester":   "3",
	}
	transcriptRecord1 := map[string]interface{}{
		"studentid":    "323456898",
		"name":         "Foo",
		"university":   "Faber College",
		"status":       "graduated",
		"totalcredits": "100",
		"course":       "Bachelors'in Computing Science",
	}

	err = createRecord(client, authToken, parameters.adminURL+studentCardsEndpoint, studentRecord1)
	if err != nil {
		return err
	}

	err = createRecord(client, authToken, parameters.adminURL+transcriptEndpoint, transcriptRecord1)
	if err != nil {
		return err
	}

	resp, err := getRecord(client, authToken, parameters.adminURL+studentCardsEndpoint+"/1")
	if err != nil {
		return err
	}

	err = verify(resp, studentRecord1)

	if err != nil {
		return err
	}

	return nil
}

// createAdminUser creates the admin user and generates the JWT token
func createAdminUser(client *http.Client, adminURL string, adminUserValues interface{}) (string, error) {
	jsonValue, err := json.Marshal(adminUserValues)

	if err != nil {
		return "", err
	}

	resp, err := client.Post(adminURL+adminURLEndpoint, "application/json", bytes.NewBuffer(jsonValue))

	if resp.StatusCode == 400 || err != nil {
		return "", fmt.Errorf("error posting the admin user: %s", err)
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			panic(err)
		}
	}()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	var adminUser strapiUser
	err = json.Unmarshal(body, &adminUser)

	if err != nil {
		return "", err
	}

	token := fmt.Sprintf("%v", adminUser.Jwt)

	err = writeToFile(strapiCodeFile, token)
	if err != nil {
		return "", err
	}

	return "Bearer " + token, nil
}

func writeToFile(name, content string) error {
	file, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE, 0644) // nolint: gosec
	if err != nil {
		return err
	}

	defer func() {
		err = file.Close()
		if err != nil {
			log.Warn("failed to close strapi file")
		}
	}()

	_, err = file.WriteString(content)
	if err != nil {
		return err
	}

	// Save file changes.
	return file.Sync()
}

// createRecord Create the record in CMS and fetch the records too
func createRecord(client *http.Client, authToken, url string, record interface{}) error {
	requestBody, err := json.Marshal(record)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(post, url, bytes.NewBuffer(requestBody))
	if err != nil {
		return err
	}

	req.Header.Set("content-type", "application/json")
	req.Header.Set("Authorization", authToken)

	resp, err := client.Do(req)
	if resp.StatusCode == 400 || err != nil {
		return fmt.Errorf("error posting the create record request: %s", err)
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			panic(err)
		}
	}()

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func getRecord(client *http.Client, authToken, url string) ([]byte, error) {
	req, err := http.NewRequest(get, url, bytes.NewBuffer(nil))
	if err != nil {
		return nil, err
	}

	req.Header.Set("content-type", "application/json")
	req.Header.Set("Authorization", authToken)

	resp, err := client.Do(req)
	if resp.StatusCode == 400 || err != nil {
		return nil, fmt.Errorf("error posting the get record request: %s", err)
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			panic(err)
		}
	}()

	return ioutil.ReadAll(resp.Body)
}

func verify(resp []byte, storedRecord map[string]interface{}) error {
	const studentIDKey = "studentid"

	const nameKey = "name"

	var fetchedRecord map[string]interface{}

	err := json.Unmarshal(resp, &fetchedRecord)

	if err != nil {
		return errors.New("failed to unmarshal the fetched record")
	}

	if storedRecord[studentIDKey] != fetchedRecord[studentIDKey] && storedRecord[nameKey] != fetchedRecord[nameKey] {
		return errors.New("fetched record doesnt match the stored record")
	}

	return nil
}
