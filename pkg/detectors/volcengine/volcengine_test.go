package volcengine

import (
	"fmt"
	"strings"
	"testing"
)

var (
	validPattern = `AccessKeyId: xxxxxxxxx
SecretAccessKey: xxxxxxx===`
	secret = ""
)

func TestVolcengine_Pattern(t *testing.T) {
	matches := keyPat.FindAllStringSubmatch(validPattern, -1)
	for _, match := range matches {
		tokenMatch := strings.TrimSpace(match[1])
		fmt.Printf(tokenMatch)
	}
}
