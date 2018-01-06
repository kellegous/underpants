package user

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Info ...
type Info struct {
	Email             string
	Name              string
	Picture           string
	LastAuthenticated time.Time
}

func isValidMessage(key []byte, sig, msg string) bool {
	s, err := base64.URLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}

	h := hmac.New(sha256.New, key)
	if _, err := h.Write([]byte(msg)); err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(s, h.Sum(nil)) == 1
}

// Encode the full user object as a base64 string that is signed with the given
// key. This value is suitable for use in a cookie.
func (i *Info) Encode(key []byte) (string, error) {
	var b bytes.Buffer
	h := hmac.New(sha256.New, key)
	w := base64.NewEncoder(base64.URLEncoding,
		io.MultiWriter(h, &b))
	if err := json.NewEncoder(w).Encode(i); err != nil {
		return "", err
	}

	if err := w.Close(); err != nil {
		return "", err
	}

	return fmt.Sprintf("%s,%s",
		base64.URLEncoding.EncodeToString(h.Sum(nil)),
		b.String()), nil
}

// Decode unmarshals an encoded and signed user.
func Decode(c string, key []byte) (*Info, error) {
	s := strings.SplitN(c, ",", 2)

	if len(s) != 2 || !isValidMessage(key, s[0], s[1]) {
		return nil, fmt.Errorf("Invalid user cookie: %s", c)
	}

	var u Info
	r := base64.NewDecoder(
		base64.URLEncoding,
		bytes.NewBufferString(s[1]))
	if err := json.NewDecoder(r).Decode(&u); err != nil {
		return nil, err
	}

	return &u, nil
}
