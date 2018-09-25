CURL ?= curl --fail -sSL
XARGS ?= xargs -I {}
BIN_DIR ?= ${HOME}/bin
PATH := $(BIN_DIR):$(PATH)

VERSION ?= $$(grep -E '^current_version' .bumpversion.cfg | sed 's/^.*= //')

MAKEFLAGS += --no-print-directory
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.SUFFIXES:

.PHONY: %/lint %/format
.PHONY: deploy

guard/program/%:
	@ which $* > /dev/null || $(MAKE) $*/install

deploy:
	@echo "make: Deploying files to S3 bucket, using aws sync"
	aws s3 sync --delete --exclude '.git/*' . s3://$(BUCKET)/$(PREFIX)
	@echo "make: Applying version tag to bucket objects"
	aws s3api list-objects --bucket $(BUCKET) --query "Contents[?starts_with(Key, \`$(PREFIX)\`)].{Key:Key}" --out text | $(XARGS) -n1 -P8 -t aws s3api put-object-tagging --bucket $(BUCKET) --tagging "TagSet=[{Key=Version,Value=$(VERSION)}]" --key {}

jq/install: JQ_VERSION ?= jq-1.5
jq/install: JQ_URL ?= https://github.com/stedolan/jq/releases/download/$(JQ_VERSION)/jq-linux64
jq/install: | $(BIN_DIR)
	@ echo "[$@]: Installing $(@D)..."
	@ echo "[$@]: JQ_URL=$(JQ_URL)"
	$(CURL) -o $(BIN_DIR)/$(@D) "$(JQ_URL)"
	chmod +x $(BIN_DIR)/$(@D)
	$(@D) --version
	@ echo "[$@]: Completed successfully!"

json/%: FIND_JSON := find . -name '*.json' -type f
json/lint: | guard/program/jq
	@ echo "[$@]: Linting JSON files..."
	$(FIND_JSON) | $(XARGS) bash -c 'cmp {} <(jq --indent 4 -S . {}) || (echo "[{}]: Failed JSON Lint Test"; exit 1)'
	@ echo "[$@]: JSON files PASSED lint test!"

json/format: | guard/program/jq
	@ echo "[$@]: Formatting JSON files..."
	$(FIND_JSON) | $(XARGS) bash -c 'echo "$$(jq --indent 4 -S . "{}")" > "{}"'
	@ echo "[$@]: Successfully formatted JSON files!"

sh/%: FIND_SH ?= find . -name '*.sh' -type f
sh/lint: | guard/program/shellcheck
	$(FIND_SH) | $(XARGS) shellcheck {}

yaml/lint: | guard/program/yamllint
	yamllint --strict .

cfn/%: FIND_CFN ?= find . -name '*.template.cfn.*' -type f
cfn/lint: | guard/program/cfn-lint
	$(FIND_CFN) | $(XARGS) cfn-lint validate --verbose {}

cfn/version:
	$(FIND_CFN) | $(XARGS) bash -c "jq -e '.Metadata.Version | test(\"^$(VERSION)$$\")' {} > /dev/null || (echo '[{}]: BAD/MISSING Cfn Version Metadata'; exit 1)"
