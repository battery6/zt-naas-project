#!/bin/bash

# User 1
curl -k -X POST https://127.0.0.1:5000/login \
-H "Content-Type: application/json" \
-d '{"username":"employee1","password":"pass123"}'

# User 2
curl -k -X POST https://127.0.0.1:5000/login \
-H "Content-Type: application/json" \
-d '{"username":"employee2","password":"pass123"}'

# Admin
curl -k -X POST https://127.0.0.1:5000/login \
-H "Content-Type: application/json" \
-d '{"username":"admin","password":"pass123"}'

# Guest
curl -k -X POST https://127.0.0.1:5000/login \
-H "Content-Type: application/json" \
-d '{"username":"guest","password":"pass123"}'

