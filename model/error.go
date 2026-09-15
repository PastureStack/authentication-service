package model

import "github.com/rancher/go-rancher/client"

// AuthServiceError structure contains the error resource definition
type AuthServiceError struct {
	client.Resource
	Status        string `json:"status"`
	Code          string `json:"code,omitempty"`
	Message       string `json:"message"`
	RequestDigest string `json:"requestDigest,omitempty"`
}
