#!/bin/bash
trap break INT
for(( ; ;))
do
	python main.py -m
done
trap - INT
echo "interrupted and ended the program..."
