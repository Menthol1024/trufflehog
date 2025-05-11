package bailian

import (
	"fmt"
	"strings"
	"testing"
)

var (
	validPattern = `curl -X POST https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions \
-H "Authorization: Bearer sk-	" \
-H "Content-Type: application/json" \
-d '{
    "model": "qwen-plus", 
    "messages": [
        {
            "role": "system",
            "content": "You are a helpful assistant."
        },
        {
            "role": "user", 
            "content": "hello"
        }
    ]
}'`
	secret = ""
)

func TestBailian_Pattern(t *testing.T) {
	matches := SKToken.FindAllStringSubmatch(validPattern, -1)
	for _, match := range matches {
		tokenMatch := strings.TrimSpace(match[1])
		fmt.Printf(tokenMatch)
	}
}
