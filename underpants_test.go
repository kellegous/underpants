package main

import (
	"testing"
	"time"
)

func BenchmarkDecodeUser(b *testing.B) {
	key, err := newKey()
	if err != nil {
		b.Error(err)
	}

	u := user{
		Email:             "email@example.com",
		Name:              "Some Person",
		Picture:           "https://lh2.googleusercontent.com/kdqfjeoijfds/AAAAAAAAAAA/AAAAAAAAAAA/abcdefghijk/photo.jpg",
		LastAuthenticated: time.Now(),
	}
	v, err := u.encode(key)
	if err != nil {
		b.Error(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := decodeUser(v, key)
		if err != nil {
			b.Error(err)
		}
	}
}
