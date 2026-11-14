#!/bin/bash
# No host/system file deletion: the fresh container is the cleanup boundary.
echo 'Use run-linux.sh; its EXIT/INT/TERM trap removes only its own disposable container.'
exit 0
