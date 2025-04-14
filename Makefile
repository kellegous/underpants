bin/underpants: $(shell find . -type f -name "*.go")
	go build -o $@ ./underpants.go

test:
	go test github.com/kellegous/underpants/auth/... \
		github.com/kellegous/underpants/config \
		github.com/kellegous/underpants/mux \
		github.com/kellegous/underpants/user \
		github.com/kellegous/underpants/util

clean:
	rm -rf bin