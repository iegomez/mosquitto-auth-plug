package main

import "C"
import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

type Response struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error"`
}

//export User
func User(host, uri, token, withTLS, verifyPeer string, port int32) bool {

	dataMap := map[string]interface{}{
		"password": token,
	}

	return httpPost(host, uri, token, withTLS, verifyPeer, dataMap, port)
}

//export Superuser
func Superuser(host, uri, token, withTLS, verifyPeer string, port int32) bool {

	var dataMap map[string]interface{}

	return httpPost(host, uri, token, withTLS, verifyPeer, dataMap, port)
}

//export Acl
func Acl(host, uri, token, withTLS, verifyPeer, topic, clientid string, acc, port int32) bool {

	dataMap := map[string]interface{}{
		"clientid": clientid,
		"topic":    topic,
		"acc":      acc,
	}

	return httpPost(host, uri, token, withTLS, verifyPeer, dataMap, port)

}

func httpPost(host, uri, token, withTLS, verifyPeer string, dataMap map[string]interface{}, port int32) bool {

	tlsStr := "http://"

	if withTLS == "true" {
		tlsStr = "https://"
	}

	fullUri := fmt.Sprintf("%s%s:%d%s", tlsStr, host, port, uri)

	client := &http.Client{Timeout: 5 * time.Second}

	if verifyPeer == "false" {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = tr
	}

	dataJson, mErr := json.Marshal(dataMap)

	if mErr != nil {
		fmt.Printf("marshal error: %v\n", mErr)
		return false
	}

	contentReader := bytes.NewReader(dataJson)
	req, reqErr := http.NewRequest("POST", fullUri, contentReader)

	if reqErr != nil {
		fmt.Printf("req error: %v\n", reqErr)
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("authorization", token)

	resp, err := client.Do(req)

	if err != nil {
		fmt.Printf("error: %v\n", err)
		return false
	}

	body, bErr := ioutil.ReadAll(resp.Body)

	if bErr != nil {
		fmt.Printf("read error: %v", bErr)
		return false
	}

	response := Response{Ok: false, Error: ""}

	jErr := json.Unmarshal(body, &response)

	if jErr != nil {
		fmt.Printf("unmarshal error: %v", jErr)
		return false
	}

	if resp.Status != "200 OK" {
		fmt.Printf("error code: %v\n", err)
		return false
	} else if !response.Ok {
		fmt.Printf("api error: %s", response.Error)
		return false
	}

	return true

}

func main() {}
