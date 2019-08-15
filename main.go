package main

import (
	"net/http"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/gin-gonic/gin"
	"github.com/pritunl/pritunl-vault/handlers"
	"github.com/pritunl/pritunl-vault/logger"
	"github.com/pritunl/pritunl-vault/vault"
)

func main() {
	logger.Init()

	err := vault.Init()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Error("main: Vault init error")
		panic(err)
		return
	}

	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	handlers.Register(router)

	server := &http.Server{
		Addr:              "127.0.0.1:9758",
		Handler:           router,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	logrus.WithFields(logrus.Fields{
		"host":     "127.0.0.1",
		"port":     "9758",
		"protocol": "http",
	}).Info("main: Starting web server")

	err = server.ListenAndServe()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Error("main: Server error")
		panic(err)
	}
}
