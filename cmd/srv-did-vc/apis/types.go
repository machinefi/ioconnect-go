package apis

type IssueTokenReq struct {
	ClientID string `json:"clientID"`
}

type IssueTokenRsp struct {
	Token string `json:"token"`
}

type VerifyTokenReq = IssueTokenRsp

type VerifyTokenRsp = IssueTokenReq
