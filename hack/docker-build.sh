#! /bin/sh
if [ "${IMAGE_TAG}" = "" ]; then
  IMAGE_TAG=latest
fi
if [ "${IMAGE_PREFIX}" = "" ]; then
  IMAGE_PREFIX=default_prefix
fi

# Build with the current (code) directory as context to avoid sending unnecessary files
docker build ${BUILD_OPT} -t ${IMAGE_PREFIX}/${TARGET}:${IMAGE_TAG} -f dockers/${TARGET}/Dockerfile .
