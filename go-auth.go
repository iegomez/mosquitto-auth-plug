package main

import "C"
import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

//export User
func User(host, uri, token, withTLS, verifyPeer string, port int32) bool {
	fmt.Printf("\n\nUSER check\n\nuri: %s\ntoken:%s \n", uri, token)

	m := map[string]interface{}{
		"password": token,
	}

	fullUri := "http"

	if withTLS == "true" {
		fullUri += "s"
	}

	fullUri = fmt.Sprintf("%s://%s:%d%s", fullUri, host, port, uri)

	mJson, _ := json.Marshal(m)
	contentReader := bytes.NewReader(mJson)
	req, _ := http.NewRequest("POST", fullUri, contentReader)
	req.Header.Set("Content-Type", "application/json")
	bearerHeader := fmt.Sprintf("%s", token)
	req.Header.Set("authorization", bearerHeader)
	fmt.Printf("Req: %v\n", req)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)

	if err != nil {
		fmt.Printf("error: %v\n", err)
		return false
	}

	fmt.Printf("resp: %v\n", resp.Body)

	if resp.StatusCode != 200 {
		fmt.Printf("error code: %v\n", err)
		return false
	}

	return true
}

//export Superuser
func Superuser(host, uri, token, withTLS, verifyPeer string, port int32) bool {
	fmt.Printf("\n\nSUPER USER check\n\nuri: %s\ntoken:%s \n", uri, token)

	var m map[string]interface{}

	fullUri := "http"

	if withTLS == "true" {
		fullUri += "s"
	}

	fullUri = fmt.Sprintf("%s://%s:%d%s", fullUri, host, port, uri)

	mJson, _ := json.Marshal(m)
	contentReader := bytes.NewReader(mJson)
	req, _ := http.NewRequest("POST", fullUri, contentReader)
	req.Header.Set("Content-Type", "application/json")
	bearerHeader := fmt.Sprintf("%s", token)
	req.Header.Set("authorization", bearerHeader)
	fmt.Printf("Req: %v\n", req)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)

	body, bErr := ioutil.ReadAll(resp.Body)
	respMap := &map[string]interface{}{}
	json.Unmarshal(body, respMap)

	if bErr != nil {
		fmt.Printf("unmarshal error: %v", bErr)
	}

	if err != nil {
		fmt.Printf("error: %v\n", err)
		return false
	}

	fmt.Printf("resp: %v\n", respMap)

	fmt.Printf("status: %s", resp.StatusCode)

	if resp.StatusCode != 200 {
		fmt.Printf("error code: %v\n", err)
		return false
	}

	return true
}

//export Acl
func Acl(host, uri, token, withTLS, verifyPeer, topic, clientid string, acc, port int32) bool {
	fmt.Printf("\n\nACL check\n\nuri: %s\ntoken:%s \n", uri, token)

	m := map[string]interface{}{
		"clientid": clientid,
		"topic":    topic,
		"acc":      acc,
	}

	fullUri := "http"

	if withTLS == "true" {
		fullUri += "s"
	}

	fullUri = fmt.Sprintf("%s://%s:%d%s", fullUri, host, port, uri)

	mJson, _ := json.Marshal(m)
	contentReader := bytes.NewReader(mJson)
	req, _ := http.NewRequest("POST", fullUri, contentReader)
	req.Header.Set("Content-Type", "application/json")
	bearerHeader := fmt.Sprintf("%s", token)
	req.Header.Set("authorization", bearerHeader)
	fmt.Printf("Req: %v\n", req)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)

	body, bErr := ioutil.ReadAll(resp.Body)
	respMap := &map[string]interface{}{}
	json.Unmarshal(body, respMap)

	if bErr != nil {
		fmt.Printf("unmarshal error: %v", bErr)
	}

	if err != nil {
		fmt.Printf("error: %v\n", err)
		return false
	}

	fmt.Printf("resp: %v\n", respMap)

	fmt.Printf("status: %s", resp.StatusCode)

	if resp.StatusCode != 200 {
		fmt.Printf("error code: %v\n", err)
		return false
	}

	return true
}

func main() {}
