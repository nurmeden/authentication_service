package config

import "github.com/nurmeden/authentication_service/pkg/utils"

type Config struct {
	MongoDBURI string
}

func NewConfig() *Config {
	return &Config{
		MongoDBURI: utils.GetEnv("MONGODB_URI", "mongodb://localhost:27017"),
	}
}
