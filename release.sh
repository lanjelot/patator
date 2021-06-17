#!/bin/bash

set -ex

DOCKER_IMAGE='lanjelot/patator'
GIT_REPO='https://github.com/lanjelot/patator'
TMP_COPY=$(mktemp -d)

git clone -b master $GIT_REPO $TMP_COPY
cd $TMP_COPY
VERSION=$(echo `git tag|sort -V|tail -1`-`git rev-parse --verify HEAD|cut -b -7`)
sed -i -e "s,^__version__.*$,__version__ = '$VERSION'," patator.py
docker build . -t $DOCKER_IMAGE:$VERSION -t $DOCKER_IMAGE:latest 

docker login
docker push $DOCKER_IMAGE
