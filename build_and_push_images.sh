#!/bin/bash

if [ $# -eq 0 ]
    then
        echo "No arguments specified"
        echo "Please specify the image name"
        exit 0
fi

echo "Building image comet1903/riseupgroup-ticketcontrol-app:$1"

docker build -t comet1903/riseupgroup-ticketcontrol-app:$1 .
docker push comet1903/riseupgroup-ticketcontrol-app:$1

docker build -t comet1903/riseupgroup-ticketcontrol-proxy:$1 ./proxy
docker push comet1903/riseupgroup-ticketcontrol-proxy:$1