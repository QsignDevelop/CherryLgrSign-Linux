//go:build !linux

package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

func initAttachMode(cfg *Config) error {
	return fmt.Errorf("attach mode is only supported on Linux")
}

func signViaAttachBridge(cmd, srcHex string, seq int) (*Response, error) {
	return nil, fmt.Errorf("attach mode is only supported on Linux")
}

func handleAttachStatus(c *gin.Context) {
	c.JSON(501, gin.H{"error": "attach mode is only supported on Linux"})
}
