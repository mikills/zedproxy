.PHONY: test e2e claude

test:
	go test -v -count=1 ./...

e2e:
	go test -tags e2e -run TestE2E -v -count=1 ./...

claude:
	go run . --convert
