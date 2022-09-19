TARGET_NAME = nic-demo
BUILD_DIR = ./
DOCKER_VER_STRING = 0.0.0

ifdef ver
DOCKER_VER_STRING = $(ver)
endif

noop:

build:
	go build -o $(BUILD_DIR)$(TARGET_NAME) .

docker:
	CGO_ENABLED=0 go build -o $(BUILD_DIR)$(TARGET_NAME) .
	docker build -t $(TARGET_NAME):$(DOCKER_VER_STRING) .

version:
	git commit -a -m "Updated prod version"
	git push origin main
	git tag $(ver)
	git push origin $(ver)
