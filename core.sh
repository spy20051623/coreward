#!/bin/bash

CPU_THRESHOLD=0.5
INTERVAL=1

usage() {
    echo "Usage: $0 <CPU_LIST>"
    echo "Examples:"
    echo "  $0 3"
    echo "  $0 0,1,2"
    echo "  $0 0-3"
    echo "  $0 0-2,5,7"
    exit 1
}

# 参数检查
if [ -z "$1" ]; then
    usage
fi

INPUT="$1"

# 获取系统CPU数量
MAX_CPU=$(nproc 2>/dev/null)
if [ -z "$MAX_CPU" ]; then
    echo "Failed to get CPU count"
    exit 1
fi
MAX_CPU=$((MAX_CPU - 1))

# 解析 CPU 列表
parse_cpu_list() {
    local input="$1"
    local result=()

    IFS=',' read -ra parts <<< "$input"
    for part in "${parts[@]}"; do
        if [[ "$part" =~ ^[0-9]+$ ]]; then
            result+=("$part")
        elif [[ "$part" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            start=${BASH_REMATCH[1]}
            end=${BASH_REMATCH[2]}

            if (( start > end )); then
                echo "Invalid range: $part"
                exit 1
            fi

            for ((i=start; i<=end; i++)); do
                result+=("$i")
            done
        else
            echo "Invalid CPU format: $part"
            exit 1
        fi
    done

    echo "${result[@]}"
}

CPU_LIST=($(parse_cpu_list "$INPUT"))

# 校验 CPU 是否越界
for cpu in "${CPU_LIST[@]}"; do
    if (( cpu < 0 || cpu > MAX_CPU )); then
        echo "CPU $cpu is out of range (0-$MAX_CPU)"
        exit 1
    fi
done

# 去重
CPU_LIST=($(printf "%s\n" "${CPU_LIST[@]}" | sort -n | uniq))

echo "Monitoring CPU(s): ${CPU_LIST[*]} (CPU > $CPU_THRESHOLD%) ..."

# 捕获 Ctrl+C
trap "echo 'Exiting...'; exit 0" SIGINT

while true; do
    ps -eo pid,psr,%cpu,comm --no-headers | \
    awk -v thr=$CPU_THRESHOLD -v cpus="${CPU_LIST[*]}" '
    BEGIN {
        split(cpus, arr, " ")
        for (i in arr) cpu_map[arr[i]] = 1
    }
    ($2 in cpu_map) && $3 > thr {
        printf "%s %s %s %s\n", $1, $2, $3, $4
    }' | while read pid psr cpu comm; do

        if [ -d "/proc/$pid" ]; then
            echo "=============================="
            echo "PID: $pid"
            echo "CPU: $cpu% (core $psr)"
            echo "CMD: $comm"

            pwdx "$pid" 2>/dev/null
            ps -p "$pid" -o user= 2>/dev/null
        fi

    done

    sleep "$INTERVAL"
done
