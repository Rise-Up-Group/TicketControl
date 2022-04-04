#!/bin/bash

if [ $# -eq 0 ]
    then
        echo "No arguments specified"
        echo "Please specify the image name"
        exit 0
fi

echo "Building image pgnhd/riseupgroup-ticketcontrol-app:$1"

docker build -t pgnhd/riseupgroup-ticketcontrol-app:$1 .
docker push pgnhd/riseupgroup-ticketcontrol-app:$1

docker build -t pgnhd/riseupgroup-ticketcontrol-proxy:$1 ./proxy
docker push pgnhd/riseupgroup-ticketcontrol-proxy:$1