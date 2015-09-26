#!/bin/bash

sudo cp nginx/nginx.conf /etc/nginx/nginx.conf
scripts/restart.sh
sudo systemctl restart nginx
