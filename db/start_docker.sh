#!/bin/bash
docker build -t transontario .
docker run -p 3000:3000 transontario
