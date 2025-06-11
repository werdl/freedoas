#!/bin/sh

i=0
while :; do
    echo "=== Run $i ==="
    /usr/local/freedoas mixerctl 1> /dev/null 2>&1
    status=$?

    if [ $status -eq 139 ]; then  # 139 = 128 + SIGSEGV
        echo "Segfault on run $i"
        ls -lt core*  # Check for new core file
        break
    fi

    i=$((i + 1))
done
