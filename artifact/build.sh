#!/bin/bash

for DIR in ./secure-allocators/*
do
  RUN_SH=$DIR/run.sh

  if [ ! -e $RUN_SH ]; then
    continue
  fi

  $RUN_SH
done
