include common.mk

lint-targets := lint-go lint-git lint-changelog

lint: $(lint-targets)

lint-changelog:
	@$(CHECK_CHANGELOG_FRAGMENTS)

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

start:
	COMPOSE_BAKE=true docker compose up --build -d

stop:
	docker compose down -v -t 0

logs:
	docker compose logs -f

# Fetch all the latest changes (including tags) from the canonical upstream git
# repository.
fetch-git:
	@$(ECHO) "Fetching the latest changes (including tags) from $(GIT_ORIGIN_REMOTE) remote..."
	@git fetch $(GIT_ORIGIN_REMOTE) --tags

# Private target for bumping project's version using the Punch tool.
# NOTE: It should not be invoked directly.
_version-bump: fetch-git
	@$(ENSURE_VALID_RELEASE_BRANCH_NAME)
	@$(PUNCH_BUMP_VERSION)
	@git add $(PUNCH_VERSION_FILE)

# Private target for assembling the Change Log.
# NOTE: It should not be invoked directly.
_changelog:
	@$(ECHO) "$(CYAN)*** Generating Change Log for version $(PUNCH_VERSION)...$(OFF)"
	@$(BUILD_CHANGELOG)
	@$(ECHO) "Next, review the staged changes, commit them and make a pull request."
	@$(WARN_BREAKING_CHANGES)

# Assemble Change Log.
# NOTE: We need to call Make recursively since _version-bump target updates
# Punch's version and hence we need Make to re-evaluate the PUNCH_VERSION
# variable.
changelog: _version-bump
	@$(MAKE) --no-print-directory _changelog

# Tag the next release.
release-tag: fetch-git
	@$(ECHO) "Checking if we can tag version $(PUNCH_VERSION) as the next release..."
	@$(ENSURE_VALID_RELEASE_BRANCH_NAME)
	@$(ENSURE_RELEASE_TAG_DOES_NOT_EXIST)
	@$(ENSURE_NO_CHANGELOG_FRAGMENTS)
	@$(ENSURE_NEXT_RELEASE_IN_CHANGELOG)
	@$(ECHO) "All checks have passed. Proceeding with tagging the $(GIT_ORIGIN_REMOTE)/$(RELEASE_BRANCH)'s HEAD with tag '$(RELEASE_TAG)'."
	@$(CONFIRM_ACTION)
	@$(ECHO) "If this appears to be stuck, you might need to touch your security key for GPG sign operation."
	@git tag --sign --message="Version $(PUNCH_VERSION)" $(RELEASE_TAG) $(GIT_ORIGIN_REMOTE)/$(RELEASE_BRANCH)
	@git push $(GIT_ORIGIN_REMOTE) $(RELEASE_TAG)
	@$(ECHO) "$(CYAN)*** Tag '$(RELEASE_TAG)' has been successfully pushed to $(GIT_ORIGIN_REMOTE) remote.$(OFF)"


release-build:
	@goreleaser $(GORELEASER_ARGS)

.PHONY: \
	$(lint-targets) lint \
	build \
	test-unit \
	test-e2e \
	start \
	stop \
	logs \
	test-e2e \
	fetch-git _version-bump _changelog changelog release-tag \
	release-build
