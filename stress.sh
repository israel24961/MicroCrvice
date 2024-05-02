#!/bin/sh

main(){
    seq -w 1 1000 | parallel -j 0  ./request.sh
}

main $@
