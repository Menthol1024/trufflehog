package doubao

import (
	"fmt"
	"strings"
	"testing"
)

var (
	validPattern = `curl https://ark.cn-beijing.volces.com/api/v3/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer 17asb5fas23c-912asda-4b65-asd9b3a-4ec7c7f88asd223" \
  -d '{
    "model": "test",
    "messages": [
        {
            "role": "user",
            "content": "hello"
        }
    ]
  }'
`
	secret = ""
)

func TestDoubao_Pattern(t *testing.T) {
	matches := SKToken.FindAllStringSubmatch(validPattern, -1)
	for _, match := range matches {
		tokenMatch := strings.TrimSpace(match[1])
		fmt.Printf(tokenMatch)
	}
}
