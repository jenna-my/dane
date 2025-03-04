
.PHONY: start run up
d ?= 
start run up: compose raw
# Start up all of the containers defined in our docker compose yaml. If Linux or
# MacOS is being used then the unix override will be applied so that the traffic
# control is able to work!
#
# The if filter expression is simply a way to check if the client os (as seen by
# docker) is linux or darwin

.PHONY: raw
raw:
# Start up all containers using an already created compose file.
	@docker-compose \
	-p dane -f built/docker-compose.yml \
	$(if \
		$(filter $(shell docker version -f {{.Client.Os}}),linux darwin),\
		-f docker/compose/docker-compose.unix.yml,\
		\
	) \
	up \
	$(if $(d),-d,)

.PHONY: stop interrupt
name ?= dane_daemon_1
stop interrupt:
# Send a SIGINT signal to a container, defaulting to the daemon.
	docker kill --signal SIGINT $(name)

.PHONY: down
down:
	@docker-compose \
	-p dane -f built/docker-compose.yml \
	down \
	--remove-orphans

.PHONY: compose
define first_time_msg
********************************************************************************
Looks like this may be your first time running DANE! Give us a moment to get the
tool ready for you. We just need to pull in a Docker image from Docker Hub.
********************************************************************************
endef
export first_time_msg
tool_dir ?= 
config_file ?= 
compose_image ?= dane-compose
compose:
	@python3 setup/build_compose.py

.PHONY: build
tag ?= latest
only ?= all
build:
# Build all (or only some) images.
ifeq ($(only),all)

	docker build \
	-f docker/iperf/Dockerfile \
	--build-arg BUILD_DATE="$(shell date --rfc-3339 seconds)" \
	-t dane-iperf:$(tag) .

	docker build \
	-f docker/daemon/Dockerfile \
	--build-arg BUILD_DATE="$(shell date --rfc-3339 seconds)" \
	-t dane-daemon:$(tag) .

	docker build \
	-f docker/lossem/Dockerfile \
	--build-arg BUILD_DATE="$(shell date --rfc-3339 seconds)" \
	-t dane-lossem:$(tag) .

	docker build \
	-f docker/compose/Dockerfile \
	--build-arg BUILD_DATE="$(shell date --rfc-3339 seconds)" \
	-t dane-compose:$(tag) .

else
	docker build \
	-f docker/$(only)/Dockerfile \
	--build-arg BUILD_DATE="$(shell date --rfc-3339 seconds)" \
	-t dane-$(only):$(tag) .
endif

.PHONY: clean
clean: stop
# Make sure everything is stopped and remove all built images
	docker rmi dane-iperf
	docker rmi dane-daemon
	docker rmi dane-lossem
	docker rmi dane-compose

.PHONY: exec
service ?= daemon
command ?= sh
exec:
# Exec into a shell for a given service.
	docker-compose \
	-p dane -f built/docker-compose.yml \
	exec $(service) $(command)
