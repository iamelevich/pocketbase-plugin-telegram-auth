lint:
	golangci-lint run -c ./golangci.yml ./...

test:
	go test ./... -v --cover

test-report:
	go test ./... -v --cover -coverprofile=coverage.out
	go tool cover -html=coverage.out

run_base_example:
	cd examples/base && go run main.go serve

run_webapp_react_example:
	cd examples/webapp-react/tg_webapp && npm i && npm run build && cd ../ && go run main.go serve

run_test_server:
	cd test && go run main.go serve

# Generate docs
# Require gomarkdoc (https://github.com/princjef/gomarkdoc)
docs:
	gomarkdoc -o README.md -e .