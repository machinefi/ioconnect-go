package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/machinefi/ioconnect-go/pkg/ioconnect"
	"net/http"
)

func RunServer(port int, doc []byte) error {
	// TODO parse doc from env
	s := &Server{}

	eng := gin.New()
	eng.Handle(http.MethodPost, "issue", s.IssueToken)
	eng.Handle(http.MethodGet, "verify", s.VerifyToken)

	s.eng = eng

	return eng.Run(fmt.Sprintf(":%d", port))
}

type Server struct {
	eng *gin.Engine
	jwk *ioconnect.JWK
}

type IssueTokenReq struct {
	ClientID string `json:"clientID"`
}

type IssueTokenRsp struct {
	Token string `json:"token"`
}

func (s *Server) IssueToken(c *gin.Context) {
	req := &IssueTokenReq{}

	if err := c.BindJSON(req); err != nil {
		c.String(http.StatusBadRequest, "failed to bind request: %v", err)
		return
	}

	token, err := s.jwk.SignTokenBySubject(req.ClientID)
	if err != nil {
		c.String(http.StatusInternalServerError, "failed to sign token: %v", err)
		return
	}
	c.JSON(http.StatusOK, &IssueTokenRsp{Token: token})
	return
}

type VerifyTokenReq = IssueTokenRsp

type VerifyTokenRsp = IssueTokenReq

func (s *Server) VerifyToken(c *gin.Context) {
	req := &VerifyTokenReq{}

	if err := c.BindJSON(req); err != nil {
		c.String(http.StatusBadRequest, "failed to bind request: %v", err)
		return
	}

	clientID, err := s.jwk.VerifyToken(req.Token)
	if err != nil {
		c.String(http.StatusInternalServerError, "failed to verify token: %v", err)
		return
	}
	c.JSON(http.StatusOK, &VerifyTokenRsp{ClientID: clientID})
	return
}
