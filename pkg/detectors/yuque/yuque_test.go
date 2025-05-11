package yuque

import (
	"fmt"
	"strings"
	"testing"
)

var (
	validPattern = ``
	secret       = ""
)

func TestYuQue_Pattern(t *testing.T) {
	matches := AAuthToken.FindAllStringSubmatch(validPattern, -1)
	for _, match := range matches {
		tokenMatch := strings.TrimSpace(match[1])
		fmt.Printf(tokenMatch)
	}
}
