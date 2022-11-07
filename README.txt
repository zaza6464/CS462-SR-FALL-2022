To compile this program:

put all of the files in a directory and run these two commands:

g++ -o client.out client.cpp common.cpp -std=c++11
g++ -o server.out server.cpp common.cpp -std=c++11

also a folder labeled "output" needs to be made in the source directory.


To run this program:

open two windows, one designated for client and the other designated for server.

After compiling run ./server.out on one window and ./client.out on the other

enter the corresponding IP adresses, pick a port that will be the same for both, and enter your desired parameters.

Have fun!

NEW RUNNING INSTRUCTIONS:
make sure makefile is in the same folder as your source code,
then type 'make client' or 'make server' to compile the code and then 
'run_client' or 'run_server' depending on which you want to run.
