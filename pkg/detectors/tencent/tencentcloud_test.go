package tencent

import (
	"fmt"
	"strings"
	"testing"
)

import (
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/regions"
	cvm "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cvm/v20170312"
)

func TestTencent_Pattern(t *testing.T) {
	credential := common.NewCredential("xxx", "xxx")
	client, _ := cvm.NewClient(credential, regions.Guangzhou, profile.NewClientProfile())
	request := cvm.NewDescribeInstancesRequest()
	response, err := client.DescribeInstances(request)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		//AuthFailure.SecretIdNotFound
		//AuthFailure.SignatureFailure TencentCloudSDKError
		if strings.Contains(err.Error(), "AuthFailure.S") {
			fmt.Println("可能是 AK/SK 错误或签名失败")
		}
		return
	}
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", response.ToJsonString())
}
