#!/bin/sh

gcc -c -I. getfacl.c  -o getfacl

# -I. - include current path
# -c compile
# -o output file name
