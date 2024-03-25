package repository

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type TokenRepository interface {
	SaveRefreshToken(userID, hashedToken string) error
	GetRefreshTokenHash(userID string) (string, error)
}

type tokenRepository struct {
	collection *mongo.Collection
}

func NewTokenRepository(collection *mongo.Collection) TokenRepository {
	return &tokenRepository{collection: collection}
}

func (r *tokenRepository) SaveRefreshToken(userID, hashedToken string) error {
	_, err := r.collection.InsertOne(context.TODO(), bson.M{
		"user_id":    userID,
		"token_hash": hashedToken,
	})

	if err != nil {
		return err
	}

	return nil
}

func (r *tokenRepository) GetRefreshTokenHash(userID string) (string, error) {
	var result struct {
		TokenHash string `bson:"token_hash"`
	}
	err := r.collection.FindOne(context.TODO(), bson.M{
		"user_id": userID,
	}).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", err
		}
		return "", nil
	}

	return result.TokenHash, nil
}
