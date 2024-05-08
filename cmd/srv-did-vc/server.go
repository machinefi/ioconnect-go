package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"

	"github.com/machinefi/ioconnect-go/cmd/srv-did-vc/apis"
	"github.com/machinefi/ioconnect-go/pkg/ioconnect"
)

func RunServer(port int, secrets ioconnect.JWKSecrets) error {
	// TODO parse doc from env
	s := &Server{}

	eng := gin.Default()
	eng.POST("issue", s.IssueToken)
	eng.POST("verify", s.VerifyToken)
	eng.GET("version", s.Version)

	s.eng = eng

	key, err := ioconnect.NewJWKBySecret(secrets)
	if err != nil {
		panic(err)
	}
	s.jwk = key
	slog.Debug("jwk generated",
		"did:io", key.DID(),
		"did:io#key", key.KID(),
		"ka did:io", key.KeyAgreementDID(),
		"ka did:io#key", key.KeyAgreementKID(),
		"doc", key.Doc(),
	)

	return eng.Run(fmt.Sprintf(":%d", port))
}

type Server struct {
	eng     *gin.Engine
	jwk     *ioconnect.JWK
	session sync.Map
}

func (s *Server) IssueToken(c *gin.Context) {
	req := &apis.IssueTokenReq{}

	if err := c.BindJSON(req); err != nil {
		c.String(http.StatusBadRequest, "failed to bind request: %v", err)
		return
	}

	token, err := s.jwk.SignToken(req.ClientID)
	if err != nil {
		c.String(http.StatusInternalServerError, "failed to sign token: %v", err)
		return
	}
	s.session.Store(token, req.ClientID)
	slog.Info("issue", "token", token, "client", req.ClientID)
	c.JSON(http.StatusOK, &apis.IssueTokenRsp{Token: token})
	return
}

func (s *Server) VerifyToken(c *gin.Context) {
	req := &apis.VerifyTokenReq{}

	if err := c.BindJSON(req); err != nil {
		c.String(http.StatusBadRequest, "failed to bind request: %v", err)
		return
	}

	clientID, err := s.jwk.VerifyToken(req.Token)
	if err != nil {
		c.String(http.StatusInternalServerError, "failed to verify token: %v", err)
		return
	}

	session, ok := s.session.Load(req.Token)
	if !ok {
		c.String(http.StatusUnauthorized, "invalid client id")
		return
	}
	clientID = session.(string)
	slog.Info("verify", "token", req.Token, "client", clientID, "session", session)

	c.JSON(http.StatusOK, &apis.VerifyTokenRsp{ClientID: clientID})
	return
}

func (s *Server) Version(c *gin.Context) {
	c.String(http.StatusOK, fmt.Sprintf("version: %s", BuildVersion))
}
