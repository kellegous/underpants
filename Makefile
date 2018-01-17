$(GOPATH)/bin/underpants: $(shell find . -type f -not -path "./vendor/*" -not -path "./.git/*")
	go install github.com/kellegous/underpants

test:
	go test github.com/kellegous/underpants/auth/... \
		github.com/kellegous/underpants/config \
		github.com/kellegous/underpants/mux \
		github.com/kellegous/underpants/user \
		github.com/kellegous/underpants/util

clean:
	rm -f $(GOPATH)/bin/underpants