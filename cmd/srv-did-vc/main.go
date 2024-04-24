package srv_did_vc

import "github.com/gin-gonic/gin"

type IssueTokenReq struct {
	ClientID string `json:"clientID"`
}

func IssueToken(c *gin.Context) {}
