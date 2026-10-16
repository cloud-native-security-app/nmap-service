# Verificación local de ms-nmap. `make verify` es la secuencia completa que
# debe quedar en verde antes de cerrar una tarea (ver docs/verification.md).

CARGO ?= cargo

.PHONY: verify fmt-check lint test test-integration doc

verify: fmt-check lint test test-integration doc

fmt-check:
	$(CARGO) fmt --check

lint:
	$(CARGO) clippy --all-targets -- -D warnings

# Tests unitarios (los que requieren Docker están marcados #[ignore]).
test:
	$(CARGO) test

# Tests de integración con Docker (testcontainers, #[ignore]). Requieren un
# daemon de Docker; no se sustituyen por mocks.
test-integration:
	$(CARGO) test -- --ignored

# rustdoc de ítems públicos (#![deny(missing_docs)]).
doc:
	$(CARGO) doc --no-deps
