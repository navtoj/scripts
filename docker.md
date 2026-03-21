### List Networks

```shell
docker network ls --no-trunc
```

#### Cleanup

```shell
docker network prune --force
```

### List Containers

```shell
docker ps --all --size --no-trunc
```

#### Environment Variables

```shell
docker exec <container> printenv
```

### Run Binary

[docker/alpine/mkcert](https://hub.docker.com/r/alpine/mkcert)

```shell
docker run -ti --rm alpine/mkcert
```

#### Cleanup

```shell
docker image prune --all --force
```
