/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package restclient

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
)

// HTTPResponse http response
type HTTPResponse struct {
	StatusCode int
	Payload    []byte
	ErrorMsg   string
}

// SendRequest sends a regular POST request to the sidetree-node
// - If post request has operation "create" then return sidetree document else no response
func SendRequest(url string, req []byte) (*HTTPResponse, error) {
	resp, err := sendHTTPRequest(url, req)
	if err != nil {
		return nil, err
	}

	return handleHTTPResp(resp)
}

// SendResolveRequest send a regular GET request to the sidetree-node and expects 'side tree document'
// as a response
func SendResolveRequest(url string) (*HTTPResponse, error) {
	client := &http.Client{}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}

	return handleHTTPResp(resp)
}

func handleHTTPResp(resp *http.Response) (*HTTPResponse, error) {
	gotBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body failed: %w", err)
	}

	if status := resp.StatusCode; status != http.StatusOK {
		return &HTTPResponse{
			StatusCode: status,
			ErrorMsg:   string(gotBody),
		}, nil
	}

	return &HTTPResponse{StatusCode: http.StatusOK, Payload: gotBody}, nil
}

func sendHTTPRequest(url string, req []byte) (*http.Response, error) {
	client := &http.Client{}

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(req))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")

	return client.Do(httpReq)
}
