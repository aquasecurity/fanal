#!/bin/bash

TEST_IMAGE=ghcr.io/aquasecurity/trivy-test-images

CURRENT=$(cd $(dirname $0);pwd)

# List the tags
TAGS=$(crane ls ${TEST_IMAGE})

# Download missing images
for tag in $TAGS
do
  dir=${CURRENT}/../testdata/fixtures/
  if [ ! -e "${dir}/${tag}.tar.gz" ]; then
    echo "Downloading $tag..."
    crane pull "${TEST_IMAGE}:${tag}" "${dir}/${tag}.tar"
    gzip "${dir}/${tag}.tar"
  fi
done
