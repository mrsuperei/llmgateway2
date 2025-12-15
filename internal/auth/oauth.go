package auth

import (
	"encoding/json"

	"golang.org/x/oauth2"
)

func TokenFromJSON(b []byte) (*oauth2.Token, error) {
	var tok oauth2.Token
	if err := json.Unmarshal(b, &tok); err != nil {
		return nil, err
	}
	return &tok, nil
}

func TokenToJSON(tok *oauth2.Token) ([]byte, error) {
	return json.Marshal(tok)
}
