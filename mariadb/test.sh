#! /bin/bash

docker run --rm --name oscar-test-mariadb -p 3306:3306 -e MYSQL_ROOT_PASSWORD=badpassword -d mariadb:10.1
# Sleep so MariaDB has time to start up
# you can check the status of mariadb with 
# docker logs oscar-test-mariadb
sleep 20
go test
docker stop oscar-test-mariadb
