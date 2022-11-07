
# CHANGE LastName to your last/surname
LASTNAME=Mahan
# CHANGE to your UWEC ID
UWECID=mahano0661

# Change only if you're working directory in Poseidon is different
POSEIDONWD=CS462/

SERVER=server
CLIENT=client

G++_FLAGS=-std=c++11

all: server client
server: server.cpp common.h packet_struct.h
	g++ ${G++_FLAGS} -o server.out server.cpp common.cpp
client: server.cpp client.h common.h packet_struct.h
	g++ ${G++_FLAGS} -o client.out client.cpp common.cpp
clean:
	if [ -f server.out ]; then rm server.out; fi
	if [ -f client.out ]; then rm client.out; fi
to_poseidon:
	scp *.[hc++] makefile ${UWECID}@poseidon0.cs.uwec.edu:/USERS/ALL/${UWECID}/${POSEIDONWD}
from_poseidon:
	scp ${UWECID}@poseidon0.cs.uwec.edu:/USERS/ALL/${UWECID}/${POSEIDONWD}/*.[hc++] .

run_client:
	./client.out
run_server:
	./server.out