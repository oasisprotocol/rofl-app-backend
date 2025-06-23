lint-targets := lint-go lint-git

lint: $(lint-targets)

lint-go:
	@golangci-lint run ./...

lint-git:
	@$(CHECK_GITLINT)

build:
	go build -v ./...

test-unit:
	go test -v $(go list ./... | grep -v '/e2e')

test-e2e:
	go test -v ./e2e/...


docker-build:
	@DOCKER_BUILDKIT=1 docker build --progress=plain \
		--tag oasislabs/rofl-app:$(USER)-dev \
		--file Dockerfile \
		.
start:
	COMPOSE_BAKE=true docker compose up --build -d

stop:
	docker compose down -v -t 0

logs:
	docker compose logs -f

.PHONY: \
	$(lint-targets) lint \
	build \
	test-unit \
	test-e2e \
	docker-build \
	start \
	stop \
	logs \
	test-e2e
