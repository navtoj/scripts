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
