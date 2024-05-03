#!/bin/bash
docker rm -f dod_ctf_web_env
docker build --tag=dod_ctf_web_env .
docker run -p 1337:1337 --rm --name=dod_ctf_web_env dod_ctf_web_env