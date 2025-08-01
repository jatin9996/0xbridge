package btc

import (
	"os"
)

// Config holds Bitcoin RPC configuration
type Config struct {
	RPCUser string
	RPCPass string
	Host    string
}

// NewConfig creates a new Bitcoin configuration from environment variables
func NewConfig() *Config {
	return &Config{
		RPCUser: getEnvOrDefault("BITCOIN_RPC_USER", "bitcoin"),
		RPCPass: getEnvOrDefault("BITCOIN_RPC_PASS", "password"),
		Host:    getEnvOrDefault("BITCOIN_RPC_HOST", "http://localhost:8332"),
	}
}

// getEnvOrDefault returns the environment variable value or a default if not set
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// NewBitcoinClient creates a new Bitcoin client with the given configuration
func NewBitcoinClient(config *Config) *BitcoinClient {
	return &BitcoinClient{
		RPCUser: config.RPCUser,
		RPCPass: config.RPCPass,
		Host:    config.Host,
	}
} 