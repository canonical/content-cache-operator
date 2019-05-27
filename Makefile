help:
	@echo "This project supports the following targets"
	@echo ""
	@echo " make help - show this text"
	@echo " make lint - run flake8"
	@echo " make test - run the functional test and unittests"
	@echo " make unittest - run the the unittest"
	@echo " make functionaltest - run the functional tests"
	@echo " make clean - remove unneeded files"
	@echo ""

lint:
	@echo "Normalising python layout with black."
	@tox -e black
	@echo "Running flake8"
	@tox -e lint

test: unittest functionaltest lint

unittest:
	@tox -e unit

functionaltest: build
	@tox -e functional

build: clean
	@echo "Building charm to base directory $(JUJU_REPOSITORY)"
	@-git describe --tags > ./repo-info
	@LAYER_PATH=./layers INTERFACE_PATH=./interfaces TERM=linux \
		JUJU_REPOSITORY=$(JUJU_REPOSITORY) charm build . --force

clean:
	@echo "Cleaning files"
	@rm -rf ./.tox
	@rm -rf ./.pytest_cache
	@rm -rf ./tests/unit/__pycache__ ./reactive/__pycache__ ./lib/__pycache__
	@rm -rf ./.coverage ./.unit-state.db

# The targets below don't depend on a file
.PHONY: lint test unittest functionaltest build clean help
