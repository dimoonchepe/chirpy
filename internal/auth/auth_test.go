package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateJWT(t *testing.T) {
	userUid := uuid.New()
	secret := "Lateralus"
	duration := time.Hour
	jwt, err := MakeJWT(userUid, secret, duration)
	if err != nil {
		t.Errorf("Failed to create JWT: %v", err)
	}
	token, err := ValidateJWT(jwt, secret)
	if err != nil {
		t.Errorf("Failed to validate JWT: %v", err)
	}
	if token != userUid {
		t.Errorf("Invalid UID in token: %s", token)
	}
}
