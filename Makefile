include $(shell test -f .tardigrade-ci || curl -sSL -o .tardigrade-ci "https://raw.githubusercontent.com/plus3it/tardigrade-ci/master/bootstrap/Makefile.bootstrap"; echo .tardigrade-ci)

VERSION ?= $$(grep -E '^current_version' .bumpversion.cfg | sed 's/^.*= //')

.PHONY: deploy
deploy:
	@echo "make: Deploying files to S3 bucket, using aws sync"
	aws s3 sync --delete --exclude '.git/*' . s3://$(BUCKET)/$(PREFIX)
	@echo "make: Applying version tag to bucket objects"
	aws s3api list-objects --bucket $(BUCKET) --query "Contents[?starts_with(Key, \`$(PREFIX)\`)].{Key:Key}" --out text | $(XARGS) -n1 -P8 -t aws s3api put-object-tagging --bucket $(BUCKET) --tagging "TagSet=[{Key=Version,Value=$(VERSION)}]" --key {}

cfn/version:
	$(FIND_CFN) | $(XARGS) bash -c "yq -e '.Metadata.Version | test(\"^$(VERSION)$$\")' {} > /dev/null || (echo '[{}]: BAD/MISSING Cfn Version Metadata'; exit 1)"
