.PHONY: install-tools test run-dry

install-tools:
	sudo bash scripts/install_tools.sh minimal

test:
	pytest -q

run-dry:
	python -m vulnez.cli run --target example.com --profile quick --modules recon --dry-run --confirm-legal
