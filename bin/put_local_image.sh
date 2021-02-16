#!/bin/bash -e

cd "$(dirname "$0")"

# load env
. ../env.sh

# setting remote repository
TAG="local-test-$(date '+%Y%m%d')"
IMAGE_CODE="code/code"
IMAGE_GITLEAKS="code/gitleaks"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
REGISTORY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

# build & push
aws ecr get-login-password --region ${AWS_REGION} \
  | docker login \
    --username AWS \
    --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

docker build --build-arg GITHUB_USER=${GITHUB_USER} --build-arg GITHUB_TOKEN=${GITHUB_TOKEN} -t ${IMAGE_CODE}:${TAG} ../src/code/
docker build --build-arg GITHUB_USER=${GITHUB_USER} --build-arg GITHUB_TOKEN=${GITHUB_TOKEN} -t ${IMAGE_GITLEAKS}:${TAG} ../src/gitleaks/

docker tag ${IMAGE_CODE}:${TAG}     ${REGISTORY}/${IMAGE_CODE}:${TAG}
docker tag ${IMAGE_GITLEAKS}:${TAG} ${REGISTORY}/${IMAGE_GITLEAKS}:${TAG}

docker push ${REGISTORY}/${IMAGE_CODE}:${TAG}
docker push ${REGISTORY}/${IMAGE_GITLEAKS}:${TAG}
