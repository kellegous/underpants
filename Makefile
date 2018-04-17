$(GOPATH)/bin/underpants: $(shell find . -type f -not -path "./vendor/*" -not -path "./.git/*")
	go install github.com/playdots/underpants

test:
	go test github.com/playdots/underpants/auth/... \
		github.com/playdots/underpants/config \
		github.com/playdots/underpants/mux \
		github.com/playdots/underpants/user \
		github.com/playdots/underpants/util

clean:
	rm -f $(GOPATH)/bin/underpants
