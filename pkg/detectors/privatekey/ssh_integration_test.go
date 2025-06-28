//go:build detectors
// +build detectors

package privatekey

import (
	"golang.org/x/crypto/ssh"
	"testing"
)

func TestFirstResponseFromSSH(t *testing.T) {
	token := "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIG7idPRLgiHkCAggA\nMBQGCCqGSIb3DQMHBAg+MLPdepHWSwSCBMgVW9LseCjfTAmF9U1qRnKsq3kIwEnW\n6aERBqs/mnmEhrXgZYgcvRRK7kD12TdHt/Nz46Ymu0h+Lrvuwtl1fHQUARTk/gFh\nonLhc9kjMUhLRIR007vJe3HvWOb/v+SBSDB38OpUxUwJmBVBuSaYLWVuPR6J5kUj\nxOgBS049lN3E9cfrHvb3bF/epIQrU0OgfyyxEvIi5n30y+tlRn3y68PY6Qd46t4Y\nUN5VZUwvJBgoRy9TGxSkiSRjhxC2PWpLYq/HMzDbcRcFF5dVAIioUd/VZ7fdgBfA\nuMW4SFfpFLDUX0aaYe+ZdA5tM0Bc0cOtG8Z0sc9JYDNNcvjmSiGCi646h8F0D3O6\nJKAQMMxQGWiyQeJ979LVjtq4lJESXA8VEKz9rV03y5xunmFCLy6dGt+6GJwXgabn\nOH7nvEv4GqAOqKc6E9je4JM+AF/oUazrfPse1KEEtsPKarazjCB/SKYtHyDJaavD\nGGjtiU9zWwGMOgIDyNmXe3ga7/TWoGOAg5YlTr6Hbq2Y/5ycgjAgPFjuXtvnoT0+\nmF5TnNfMAqTgQsE2gjhonK1pdlOen0lN5FtoUXp3CXU0dOq0J70GiX+1YA7VDn30\nn5WNAgfOXX3l3E95jGN370pHXyli5RUNW0NZVHV+22jlNWCVtQHUh+DVswQZg+i5\n+DqaIHz2jUetMo7gWtqGn/wwSopOs87VM1rcALhZL4EsJ+Zy81I/hA32RNnGbuol\nNAiZh+0KrtTcc/fPunpd8vRtOwGphM11dKucozUufuiPG2inR3aEqt5yNx54ec/f\nJ6nryWRYiHEA/rCU9MSBM9cqKFtEmy9/8oxV41/SPxhXjHwDlABWTtFuJ3pf2sOF\nILSYYFwB0ZGvdjE5yAJFBr9efno/L9fafmGk7a3vmVgK2AmUC9VNB5XHw1GjF8OP\naQAXe4md9Bh0jk/D/iyp7e7IWNssul/7XejhabidWgFj6EXc9YxE59+FlhDqyMhn\nV6houc+QeUXuwsAKgRJJhJtpv/QSZ5BI3esxHHUt3ayGnvhFElpAc0t7C/EiXKIv\nDAFYP2jksBqijM8YtEgPWYzEP5buYxZnf/LK7FDocLsNcdF38UaKBbeF90e7bR8j\nSHspG9aJWICu8Yawnh8zuy/vQv+h9gWyGodd2p9lQzlbRXrutbwfmPf7xP6nzT9i\n9GcugJxTaZgkCfhhHxFk/nRHS2NAzagKVib1xkUlZJg2hX0fIFUdYteL1GGTvOx5\nm3mTOino4T19z9SEdZYb2OHYh29e/T74bJiLCYdXwevSYHxfZc8pYAf0jp4UnMT2\nf7B0ctX1iXuQ2uZVuxh+U1Mcu+v0gDla1jWh7AhcePSi4xBNUCak0kQip6r5e6Oi\nr4MIyMRk/Pc5pzEKo8G6nk26rNvX3aRvECoVfmK7IVdsqZ6IXlt9kOmWx3IeKzrO\nJ5DxpzW+9oIRZJgPTkc4/XRb0tFmFQYTiChiQ1AJUEiCX0GpkFf7cq61aLGYtWyn\nvL2lmQhljzjrDo15hKErvk7eBZW7GW/6j/m/PfRdcBI4ceuP9zWQXnDOd9zmaE4b\nq3bJ+IbbyVZA2WwyzN7umCKWghsiPMAolxEnYM9JRf8BcqeqQiwVZlfO5KFuN6Ze\nle4=\n-----END ENCRYPTED PRIVATE KEY-----"
	ssh.ParseRawPrivateKey([]byte(Normalize(token)))
	//ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	//defer cancel()
	//testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors4")
	//if err != nil {
	//	t.Fatalf("could not get test secrets from GCP: %s", err)
	//}
	//secretGitHub := testSecrets.MustGetField("PRIVATEKEY_GITHUB")
	//
	//parsedKey, err := ssh.ParseRawPrivateKey([]byte(Normalize(secretGitHub)))
	//if err != nil {
	//	t.Fatalf("could not parse test secret: %s", err)
	//}
	//println(parsedKey)
	//
	//output, err := firstResponseFromSSH(ctx, parsedKey, "git", "github.com:22")
	//if err != nil {
	//	t.Fail()
	//}
	//
	//if len(output) == 0 {
	//	t.Fail()
	//}
}
