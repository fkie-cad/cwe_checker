#!/bin/bash
pat=".*\.ml(i|l|y)?$"
if [[ $1 =~ $pat ]]; 
then
    s1=$(cat $1)
    s2=$(ocp-indent $1)
    if [ "$s1" == "$s2" ]
    then
        exit 0
    else
        echo "$1: ocp-indent"
        exit 1
    fi
fi
exit 0
