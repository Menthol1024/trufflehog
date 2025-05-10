package dingdoc

import (
	"fmt"
	"strings"
	"testing"
)

var (
	validPattern = `[{
		"_id": "1a8d0cca-e1a9-4318-bc2f-f5658ab2dcb5",
		"name": "HuggingFace",
		"type": "Detector",
		"api": true,
		"authentication_type": "",
		"verification_url": "https://api.example.com/example",
		"test_secrets": {
			"huggingface_secret": "MzA0NTIyNzk0OUJDrRZvQdOxxxxxxxxxxxxxxxxxxxxxx"
		},
		"expected_response": "200",
		"method": "GET",
		"deprecated": false
	}]`
	secret = "MzA0NTIyNzk0OUJDrxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
)

func TestDingDoc_Pattern(t *testing.T) {
	matches := AToken.FindAllStringSubmatch(validPattern, -1)
	for _, match := range matches {
		tokenMatch := strings.TrimSpace(match[1])
		fmt.Printf(tokenMatch)
	}
}
