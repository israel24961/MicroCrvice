#!/bin/sh
#if some error occurs, stop the script
set -e
BUILD_PATH='./build'

main(){
  mkdir -p $BUILD_PATH
  mkdir -p $BUILD_PATH/debug
  mkdir -p $BUILD_PATH/release

  #Check if submodules are initialized (/extern)
  if [ ! -d "extern" ]; then
    pinf "Submodules not initialized, runnning git submodule update --init\n"
    e=$(git submodule update --init)
    if [ -n "$e" ]; then
      pinf "Submodule initialization failed\n"
      exit 1
    fi
  fi

  if [ "$kind" = "d" ] || [ "$kind" = "debug" ]; then
    BUILD_PATH="$BUILD_PATH/debug"
    BUILD_TYPE='Debug'
  elif [ "$kind" = "r" ] || [ "$kind" = "release" ]; then
    BUILD_PATH="$BUILD_PATH/release"
    BUILD_TYPE='Release'
  fi


  ln -sf $BUILD_PATH/compile_commands.json .
  
 CC="$compiler" cmake  -S . -B "$BUILD_PATH" -DCMAKE_EXPORT_COMPILE_COMMANDS=True \
    -DCMAKE_BUILD_TYPE=$BUILD_TYPE $EXTRA_DEFS || bye "CMake failed" ;
  cd $BUILD_PATH || perr "No BUILD_PATH"


  #make dry if dry_run is set
  if [ "$dry_run" = "dry" ]; then
    printf "\033[32m"
    make -n -j4 || bye "Dry run failed"
    exit 0
  else #make and if execute is set, execute
    make -j4  || bye "Make failed"
    if [ "$execute" = "execute" ]; then
      ./CommentsBackend || bye "Execution failed"

    fi
  fi

  if [ "$execute" = "test" ]; then
    ctest || bye "Test failed"
    return 0
  fi
  if [ "$execute" = "gdb" ]; then
    gdb -tui ./CommentsBackend  || bye "GDB failed"
    return 0
  fi

}
#parses the command line arguments with getopt
options(){
  #set defaults
  kind='debug'
  dry_run=''
  execute=''
  compiler='gcc'
  #parse arguments
  while getopts 'derhgtc' flag; do
    case "${flag}" in
      d) kind='debug' ;;
      e) execute='execute' ;;
      r) kind='release' ;;
      h) command_help ;
        exit 0 ;;
      g) execute='gdb' ;;
      t) execute='test' ;;
      c) compiler='clang' ;;
      *) command_help;
        bye "Unexpected option ${flag}" ;;
    esac
  done
  shift $((OPTIND-1))
}
command_help(){
  printf "Usage: build.sh [OPTIONS]\n"
  printf "Builds the project with cmake and make\n"
  printf "Options:\n"
  printf "  -d, --debug     Build in debug mode\n"
  printf "  -r, --release   Build in release mode\n"
  printf "  -e, --execute   Execute the program after building\n"
  printf "  -t  --test      Execute the tests\n"
  printf "  -g --gdb        Execute the program with gdb\n"
  printf "  -h, --help      Show this help message\n"
  printf "  -c, --clang    Use clang as compiler\n"
  printf "  --dry           Dry run, only prints the commands\n"
  printf "  --verbose       Verbose output\n"
  printf "Common usage:\n"
  printf "  ./build.sh -ed Execute in debug mode\n"
  printf "  ./build.sh -er Execute in release mode\n"
}
perr(){
    printf "\033[31m%s\033[0m" "$1"
}
pinf(){
    printf "\033[32m%s\033[0m" "$1"
}
bye(){
    perr "$1"
    exit 1
}
options $@
main 

