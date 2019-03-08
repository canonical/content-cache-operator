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
	@echo "Running flake8"
	@tox -e lint

test: unittest functionaltest lint

unittest:
	@tox -e unit

functionaltest:
	@tox -e functional

clean:
	@echo "Cleaning files"
	@rm -rf ./.tox
	@rm -rf ./.pytest_cache

# The targets below don't depend on a file
.PHONY: lint test unittest functionaltest clean help
