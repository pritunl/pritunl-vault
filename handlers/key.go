package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/pritunl/pritunl-vault/utils"
	"github.com/pritunl/pritunl-vault/vault"
)

func keyGet(c *gin.Context) {
	payload, err := vault.Primary.GetServerKey()
	if err != nil {
		utils.AbortWithError(c, 500, err)
		return
	}

	c.JSON(200, payload)
}

func keyPost(c *gin.Context) {
	payload := &vault.Payload{}

	err := c.Bind(payload)
	if err != nil {
		utils.AbortWithError(c, 500, err)
		return
	}

	err = vault.Primary.LoadHostKey(payload)
	if err != nil {
		utils.AbortWithError(c, 500, err)
		return
	}

	c.Status(200)
}

func masterPost(c *gin.Context) {
	payload := &vault.Payload{}

	err := c.Bind(payload)
	if err != nil {
		utils.AbortWithError(c, 500, err)
		return
	}

	err = vault.Primary.LoadMasterKey(payload)
	if err != nil {
		utils.AbortWithError(c, 500, err)
		return
	}

	returnPayload, err := vault.Primary.GetCryptoKeys()
	if err != nil {
		utils.AbortWithError(c, 500, err)
		return
	}

	c.JSON(200, returnPayload)
}

func initGet(c *gin.Context) {
	initKeyData, err := vault.Primary.GetInitKey()
	if err != nil {
		utils.AbortWithError(c, 500, err)
		return
	}

	c.String(200, initKeyData)
}
