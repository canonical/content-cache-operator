CHARM_REPO = git+ssh://git.launchpad.net/content-cache-charm
CHARM_NAME = $(shell awk '/^name:/ { print $$2 }' metadata.yaml)
CHARM_BUILD_DIR ?= ~/tmp
CHARM_DEST_DIR ?= $(CHARM_BUILD_DIR)/$(CHARM_NAME)

$(CHARM_BUILD_DIR):
	mkdir -p $@

help:
	@echo "This project supports the following targets"
	@echo ""
	@echo " make help - show this text"
	@echo " make lint - run flake8"
	@echo " make test - run the functional test and unittests"
	@echo " make unittest - run the the unittest"
	@echo " make functional - run the functional tests"
	@echo " make build - build the charm"
	@echo " make clean - remove unneeded files"
	@echo ""

lint:
	@echo "Normalising python layout with black."
	@tox -e black
	@echo "Running flake8"
	@tox -e lint

test: lint unittest functional

unittest:
	@tox -e unit

functional: build
	@tox -e functional

build: clean | $(CHARM_BUILD_DIR)
	$(eval TMP_CHARM_BUILD_DIR = $(shell mktemp -d -p $(CHARM_BUILD_DIR) charm-build.$(CHARM_NAME).XXXXXXXX))
	@if [ -z $(CHARM_NAME) ]; then \
		echo "Unable to work out charm name from metadata.yaml"; \
		exit 1; \
	fi
	charm build -o $(TMP_CHARM_BUILD_DIR)
	if [ -d $(CHARM_DEST_DIR)/ ]; then \
		git -C $(CHARM_DEST_DIR)/ pull; \
	else \
		git clone -- $(CHARM_REPO) $(CHARM_DEST_DIR)/; \
	fi
	rsync -a --exclude .git --delete -- $(TMP_CHARM_BUILD_DIR)/builds/$(CHARM_NAME)/ $(CHARM_DEST_DIR)/
	@echo "Built charm in $(CHARM_DEST_DIR)"
	rm -rf -- $(TMP_CHARM_BUILD_DIR)

clean:
	@echo "Cleaning files"
	@rm -rf ./.tox
	@rm -rf ./.pytest_cache
	@rm -rf ./tests/unit/__pycache__ ./reactive/__pycache__ ./lib/__pycache__
	@rm -rf ./.coverage ./.juju-persistent-config ./.unit-state.db

# The targets below don't depend on a file
.PHONY: lint test unittest functionaltest build clean help
