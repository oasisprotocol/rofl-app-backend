lint:
	@golangci-lint run ./...

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
	lint \
	docker-build \
	start \
	stop \
	logs
