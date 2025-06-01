package huaweicloud

import (
	"fmt"
	obs "github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	"testing"
)

var (
	validPattern = `x`
	secret       = ""
)

// InvalidAccessKeyId
// SignatureDoesNotMatch
// Credentials 结构体用于保存 AK/SK
func TestYuQue_Pattern(t *testing.T) {
	//用户的Access Key ID和Secret Access Key
	ak, sk := "HPUAHM3I58NFXQ0G7VEG", "LGSiVDQwxwqq5ePYT8JtecWKR19KTZgLLkZ0QW1m"
	endPoint := "https://obs.cn-north-4.myhuaweicloud.com"
	obsClient, err := obs.New(ak, sk, endPoint /*, obs.WithSecurityToken(securityToken)*/)
	if err != nil {
		fmt.Printf("Create obsClient error, errMsg: %s", err.Error())
	}
	input := &obs.ListBucketsInput{}
	input.QueryLocation = true
	input.BucketType = obs.OBJECT
	output, err := obsClient.ListBuckets(input)
	if err == nil {
		fmt.Printf("List buckets successful!\n")
		fmt.Printf("RequestId:%s\n", output.RequestId)
		for index, val := range output.Buckets {
			fmt.Printf("Bucket[%d]-Name:%s,CreationDate:%s\n", index, val.Name, val.CreationDate)
		}
		return
	}
	fmt.Printf("List buckets fail!\n")
	if obsError, ok := err.(obs.ObsError); ok {
		fmt.Println("An ObsError was found, which means your request sent to OBS was rejected with an error response.")
		fmt.Println(obsError.Error())
	} else {
		fmt.Println("An Exception was found, which means the client encountered an internal problem when attempting to communicate with OBS, for example, the client was unable to access the network.")
		fmt.Println(err)
	}
}
