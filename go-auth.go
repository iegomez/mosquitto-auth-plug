package main

import "C"
import "fmt"

//export User
func User(uri, token string) bool {
	fmt.Printf("uri: %s\ntoken:%s \n", uri, token)
	return true
}

//export Superuser
func Superuser(uri, token string) bool {
	fmt.Printf("uri: %s\ntoken:%s \n", uri, token)
	return true
}

//export Acl
func Acl(uri, token, topic string) bool {
	fmt.Printf("uri: %s\ntoken:%s \ntopic: %s\n", uri, token)
	return true
}

func main() {}
