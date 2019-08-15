package handlers

import (
	"fmt"
	"net/http"

	"github.com/Sirupsen/logrus"
	"github.com/dropbox/godropbox/errors"
	"github.com/gin-gonic/gin"
	"github.com/pritunl/pritunl-vault/utils"
)

func Limiter(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4000000)
}

func Validate(c *gin.Context) {
	if c.Request.Header.Get("User-Agent") != "pritunl" {
		c.AbortWithStatus(401)
		return
	}
	c.Next()
}

func Recovery(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			logrus.WithFields(logrus.Fields{
				"error": errors.New(fmt.Sprintf("%s", r)),
			}).Error("middlewear: Handler panic")
			utils.AbortWithStatus(c, 500)
			return
		}
	}()
	defer func() {
		if c.Errors != nil && len(c.Errors) != 0 {
			logrus.WithFields(logrus.Fields{
				"error": c.Errors,
			}).Error("middlewear: Handler error")
		}
	}()

	c.Next()
}

func Register(engine *gin.Engine) {
	engine.Use(Limiter)
	engine.Use(Validate)
	engine.Use(Recovery)

	engine.GET("/key", keyGet)
	engine.POST("/key", keyPost)
	engine.GET("/init", initGet)
	engine.POST("/master", masterPost)
}
