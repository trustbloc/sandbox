/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package createdemodata

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

const testURL = "http://localhost:1337"

func TestStartCmdContents(t *testing.T) {
	startCmd := GetStartCmd()

	require.Equal(t, "create-demo-data", startCmd.Use)
	require.Equal(t, "create demo data", startCmd.Short)
	require.Equal(t, "Start populating data in strapi with default studentcards and transcripts", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, hostURLFlagShorthand, hostURLFlagUsage)
}

func TestStartCmdWithBlankHostArg(t *testing.T) {
	startCmd := GetStartCmd()

	args := []string{"--" + hostURLFlagName, ""}
	startCmd.SetArgs(args)

	err := startCmd.Execute()

	require.Equal(t, errMissingAdminURL.Error(), err.Error())
}

func TestStartCmdWithMissingHostArg(t *testing.T) {
	startCmd := GetStartCmd()
	err := startCmd.Execute()

	require.Equal(t,
		"Neither host-url (command line flag) nor STRAPI-DEMO_ADMIN_URL (environment variable) have been set.",
		err.Error())
}
func TestStartEdgeStoreWithBlankHost(t *testing.T) {
	parameters := &strapiDemoParameters{adminURL: ""}

	err := startStrapiDemo(parameters)
	require.NotNil(t, err)
	require.Equal(t, errMissingAdminURL, err)
}

func checkFlagPropertiesCorrect(t *testing.T, cmd *cobra.Command, flagName, flagShorthand, flagUsage string) {
	flag := cmd.Flag(flagName)

	require.NotNil(t, flag)
	require.Equal(t, flagName, flag.Name)
	require.Equal(t, flagShorthand, flag.Shorthand)
	require.Equal(t, flagUsage, flag.Usage)
	require.Equal(t, "", flag.Value.String())

	flagAnnotations := flag.Annotations
	require.Nil(t, flagAnnotations)
}
func TestAdminUserAndCreateRecordWithRoundTripper(t *testing.T) {
	t.Run("add the admin user ", func(t *testing.T) {
		client := NewTestClient(func(req *http.Request) *http.Response {
			// Test request parameters
			return &http.Response{
				// Send response to be tested
				Body: ioutil.NopCloser(bytes.NewBufferString(`{
	 			"jwt": "eyJhbGciOiJIU",
				"user": {
        		"id": 12 }
	}`)),
			}
		})
		adminUserValues := map[string]string{"username": "strapi"}
		token, err := createAdminUser(client, testURL, adminUserValues)
		require.NotNil(t, token)
		require.Nil(t, err)
		require.Equal(t, "Bearer eyJhbGciOiJIU", token)
	})
	t.Run("add the student record and verify", func(t *testing.T) {
		client2 := NewTestClient(func(req *http.Request) *http.Response {
			// Test request parameters
			return &http.Response{
				// Send response to be tested
				Body: ioutil.NopCloser(bytes.NewBufferString(`{
		"id" : 1,
	 	"studentid": "1234568",
		"name":      "Tanu"
	}`)),
			}
		})
		parameters := &strapiDemoParameters{client: client2, adminURL: testURL}
		err := startStrapiDemo(parameters)
		require.Nil(t, err)
	})
	t.Run("error while verifying record", func(t *testing.T) {
		client2 := NewTestClient(func(req *http.Request) *http.Response {
			// Test request parameters
			return &http.Response{
				// Send response to be tested
				Body: ioutil.NopCloser(bytes.NewBufferString(`{
		"id" : 1,
	 	"when": "test"
	}`)),
			}
		})
		parameters := &strapiDemoParameters{client: client2, adminURL: testURL}
		err := startStrapiDemo(parameters)
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "fetched record doesnt match the stored record")
	})
	t.Run("error while getting record ", func(t *testing.T) {
		client := NewTestClient(func(req *http.Request) *http.Response {
			return &http.Response{
				Body: ioutil.NopCloser(r{}),
			}
		})
		parameters := &strapiDemoParameters{client: client, adminURL: testURL}
		err := startStrapiDemo(parameters)
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "error in reading http response")
	})
}
func TestCreateAdminUserError(t *testing.T) {
	client := NewTestClient(func(req *http.Request) *http.Response {
		// Test request parameters
		return &http.Response{
			// Send response to be tested
			Body: ioutil.NopCloser(bytes.NewBufferString(`OK`)),
		}
	})
	adminUserValues := map[string]string{"username": "strapi"}
	token, err := createAdminUser(client, testURL, adminUserValues)
	require.Equal(t, "", token)
	require.Contains(t, err.Error(), "invalid character")

	parameters := &strapiDemoParameters{client: client, adminURL: testURL}

	err = startStrapiDemo(parameters)
	require.NotNil(t, err)

	token, err = createAdminUser(client, "}}|}", make(chan int))
	require.Equal(t, "", token)
	require.Contains(t, err.Error(), "json: unsupported type: chan int")

	err = createRecord(client, token, testURL+studentCardsEndpoint, make(chan int))
	require.NotNil(t, err.Error())
	require.Contains(t, err.Error(), "json: unsupported type: chan int")

	t.Run("add the admin user ", func(t *testing.T) {
		client := NewTestClient(func(req *http.Request) *http.Response {
			// Test request parameters
			return &http.Response{
				StatusCode: 400,
			}
		})
		adminUserValues := map[string]string{"username": "strapi"}
		token, err := createAdminUser(client, testURL, adminUserValues)
		require.NotNil(t, token)
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "error posting the admin user:")
	})
}

func TestCreateRecord(t *testing.T) {
	client := NewTestClient(func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode: 400,
		}
	})
	studentRecord1 := map[string]interface{}{
		"studentid": "1234568",
		"name":      "Tanu",
	}

	t.Run("create record error", func(t *testing.T) {
		err := createRecord(client, "token", testURL+studentCardsEndpoint, studentRecord1)
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "error posting the create record request")
	})

	client2 := NewTestClient(func(req *http.Request) *http.Response {
		return &http.Response{
			Body: ioutil.NopCloser(r{}),
		}
	})

	t.Run("error in reading the http response", func(t *testing.T) {
		err := createRecord(client2, "token", testURL+studentCardsEndpoint, studentRecord1)
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "error in reading http response")
	})
	t.Run("error in reading the http response", func(t *testing.T) {
		err := createRecord(client2, "token", testURL+studentCardsEndpoint, make(chan int))
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "json: unsupported type: chan int")
	})
}
func TestGetRecord(t *testing.T) {
	client := NewTestClient(func(req *http.Request) *http.Response {
		return &http.Response{
			Body: ioutil.NopCloser(r{}),
		}
	})

	t.Run("error in reading the http response", func(t *testing.T) {
		resp, err := getRecord(client, "token", testURL+studentCardsEndpoint)
		require.NotNil(t, err)
		require.Empty(t, resp)
		require.Contains(t, err.Error(), "error in reading http response")
	})

	client2 := NewTestClient(func(req *http.Request) *http.Response {
		// Test request parameters
		return &http.Response{
			// Send response to be tested
			Body: ioutil.NopCloser(bytes.NewBufferString(`OK`)),
		}
	})

	t.Run("error in get Record reading the http response", func(t *testing.T) {
		resp, err := getRecord(client2, "token", "%%%%3554")
		require.NotNil(t, err)
		require.Empty(t, resp)
		require.Contains(t, err.Error(), "invalid URL escape")
	})
	t.Run("error in create admin user reading the http response", func(t *testing.T) {
		token, err := createAdminUser(client, testURL+studentCardsEndpoint, nil)
		require.NotNil(t, err)
		require.Equal(t, token, "")
		require.Contains(t, err.Error(), "error in reading http response")
	})

	t.Run("get record bad request error", func(t *testing.T) {
		client := NewTestClient(func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: 400,
			}
		})
		resp, err := getRecord(client, "token", testURL+studentCardsEndpoint)
		require.NotNil(t, err)
		require.Empty(t, resp)
		require.Contains(t, err.Error(), "error posting the get record request")
	})
}

func TestVerify(t *testing.T) {
	storedRecord := map[string]interface{}{
		"studentid": "1234568",
		"name":      "Tanu",
	}

	t.Run("Successful Verification ", func(t *testing.T) {
		resp := `
    {
		"id" :"1",
		"studentid": "1234568",
    	"name":      "Tanu"
	}`
		err := verify([]byte(resp), storedRecord)
		require.NoError(t, err)
	})

	t.Run("Invalid Resp and failed to unmarshal", func(t *testing.T) {
		invalidResp := `
    {
		"id" :"1",
	}`
		err := verify([]byte(invalidResp), storedRecord)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal the fetched record")
	})

	t.Run("Invalid fetched response", func(t *testing.T) {
		missingKeysResp := `
    {
		"university": "Faber College",
   		 "score":      "200"
	}`
		err := verify([]byte(missingKeysResp), storedRecord)
		require.Error(t, err)
		require.Contains(t, err.Error(), "fetched record doesnt match the stored record")
	})
}

// RoundTripFunc RoundTripper is an interface representing the ability to execute a single HTTP transaction,
// obtaining the Response for a given Request.
// https://golang.org/pkg/net/http/#RoundTripper
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip http.RoundTripper Interface has just one method RoundTrip(*Request) (*Response, error)
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

// NewTestClient returns *http.Client with Transport replaced to avoid making real calls
func NewTestClient(fn RoundTripFunc) *http.Client { //nolint : interfacer
	return &http.Client{
		Transport: fn,
	}
}

type r struct{}

func (r) Read(p []byte) (n int, err error) {
	return 0, errors.New(`error in reading http response`)
}
