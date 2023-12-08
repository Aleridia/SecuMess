#!/bin/bash
tmp=0
rm result.txt
touch result.txt
while IFS= read -r line; do
    tmp=$(($tmp + 1))
    echo "Text read from file: $line"
    if [[ $tmp == 4 ]]; then
        var=$(echo "$line" | tr -d '\n\t\r')
        echo "$var%00" >> result.txt
    fi
    if [[ $tmp == 8 ]]; then
        tmp=0
    fi
done < dirTraversal-nix.txt
