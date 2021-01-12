# bhportscan
Port scan target(s) using nmap
Based on bash and `gargs` developed by `brentp`

## Setup 
Setup the docker container by running the following command:
```
docker build -t bhportscan:latest .
```

## Usage

- To scan a single target e.g. `www.msn.com`:
```
docker run -v /opt/dockershare:/opt/dockershare --rm bhportscan:latest -c "./bhportscan.sh www.msn.com"
```

- To scan multiple targets in shared file e.g `/opt/dockershare/targets/targets.txt`:
```
docker run -v /opt/dockershare:/opt/dockershare --rm bhportscan:latest -c "cat /opt/dockershare/targets/targets.txt | gargs --procs 10 './bhportscan.sh {}'"
```

- To scan the assets in the IP range `10.10.10.0/24`: 
```
docker run -v /opt/dockershare:/opt/dockershare --rm bhportscan:latest -c "./bhexpandiprange.sh 10.10.10.0/24 | gargs --procs 10 './bhportscan.sh {}'"
```