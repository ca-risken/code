#! /bin/sh
if [ "${IMAGE_TAG}" = "" ]; then
  IMAGE_TAG=latest
fi
if [ "${IMAGE_PREFIX}" = "" ]; then
  IMAGE_PREFIX=default_prefix
fi

# Determine build context: if we're in code directory, go to parent; otherwise use current dir
if [ -d "../datasource-api" ] && [ -d "../code" ]; then
  # We're in code directory, build from parent
  cd ..
  docker build ${BUILD_OPT} -t ${IMAGE_PREFIX}/${TARGET}:${IMAGE_TAG} -f code/dockers/${TARGET}/Dockerfile .
else
  # Build from current directory (assumes parent context)
  docker build ${BUILD_OPT} -t ${IMAGE_PREFIX}/${TARGET}:${IMAGE_TAG} -f dockers/${TARGET}/Dockerfile .
fi
