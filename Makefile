NAME=registry-puller
CONTAINER_NAME=knrc/$(NAME)
CONTAINER_TAG=1.0

.PHONY: all build docker clean

all: build docker

build:
	GOOS=linux GOARCH=amd64 go build -o docker/$(NAME)

docker:
	docker build docker -t $(CONTAINER_NAME):$(CONTAINER_TAG)

clean:
	docker rmi $(CONTAINER_NAME):$(CONTAINER_TAG)
