#!/bin/bash
source /home/sosuts/repository/tiny-tls-py/.venv/bin/activate
python3 /home/sosuts/repository/tiny-tls-py/src/tiny_tls_py/server.py &
sleep 2
openssl s_client -connect localhost:10003 -tls1_3 -debug -msg
