#! /bin/sh
if [ "${IMAGE_TAG}" = "" ]; then
  IMAGE_TAG=latest
fi
if [ "${IMAGE_PREFIX}" = "" ]; then
  IMAGE_PREFIX=default_prefix
fi

# Build from parent directory to match Dockerfile expectations (COPY code/..., COPY datasource-api/...)
# If we're in code directory, go to parent; otherwise assume we're already in parent
if [ -d "../code" ] && [ "$(basename $(pwd))" = "code" ]; then
  cd ..
fi

# Build with parent context (required for Dockerfile COPY commands)
docker build ${BUILD_OPT} -t ${IMAGE_PREFIX}/${TARGET}:${IMAGE_TAG} -f code/dockers/${TARGET}/Dockerfile .
