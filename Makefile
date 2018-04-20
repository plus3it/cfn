.PHONY: deploy

deploy:
	@echo "make: Deploying files to S3 bucket, using aws sync"
	aws s3 sync --delete --exclude '.git/*' . s3://$(BUCKET)/$(PREFIX)
	@echo "make: Applying version tag to bucket objects"
	aws s3api list-objects --bucket $(BUCKET) --query "Contents[?starts_with(Key, \`$(PREFIX)\`)].{Key:Key}" --out text | xargs -n1 -P8 -I {} -t aws s3api put-object-tagging --bucket $(BUCKET) --tagging "TagSet=[{Key=Version,Value=$(VERSION)}]" --key {}
