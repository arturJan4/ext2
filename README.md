# Simulated EXT2
## Description
ext2 filesystem, altough not implemented completely, but simulated (with some functions used as an abstraction of lower-level stuff)

parts not inside `ext2fs.c` were provided by the lecturer!, also some CSAPP libraries were used 

## Features
implements data structures from first revision of ext2, so that syscalls like mount(), open(), read(), readlink(), getdirentries(), stat(), etc. work

## How to run
`make` -> for building whole project   
`make clean` -> to clean directory from executable and object files  
`make format` -> to format all .c files  
`make test` -> to run test provided by the lecturer (sometimes may fail)  

