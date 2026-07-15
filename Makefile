GFORTH ?= gforth

.PHONY: test test-m1 test-executor test-sighash

test: test-m1 test-executor test-sighash

test-m1:
	$(GFORTH) tests/run-m1.fs -e bye

test-executor:
	$(GFORTH) tests/run-executor.fs -e bye

test-sighash:
	$(GFORTH) tests/run-sighash.fs -e bye
