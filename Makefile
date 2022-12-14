help:
	@echo "This project supports the following targets"
	@echo ""
	@echo " make help - show this text"
	@echo " make lint - run flake8"
	@echo " make test - run the unit and integration tests"
	@echo " make unittest - run the unit tests"
	@echo " make integration - run the integration tests"
	@echo " make clean - remove unneeded files"
	@echo ""

blacken:
	@echo "Normalising python layout with black."
	@tox -e black

lint: blacken
	@echo "Running flake8"
	@tox -e lint

test: lint unittest

unittest:
	@tox -e unit

integration:
	@tox -e integration

clean:
	@echo "Cleaning files"
	@git clean -ffXd

# The targets below don't depend on a file
.PHONY: lint test unittest integration build clean help
