
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
server: Kamke_Kranich_Mahan_server.cpp Kamke_Kranich_Mahan_common.h Kamke_Kranich_Mahan_packet_struct.h
	g++ ${G++_FLAGS} -o Kamke_Kranich_Mahan_server.out Kamke_Kranich_Mahan_server.cpp Kamke_Kranich_Mahan_common.cpp
client: Kamke_Kranich_Mahan_server.cpp Kamke_Kranich_Mahan_client.h Kamke_Kranich_Mahan_common.h Kamke_Kranich_Mahan_packet_struct.h
	g++ ${G++_FLAGS} -o Kamke_Kranich_Mahan_client.out Kamke_Kranich_Mahan_client.cpp Kamke_Kranich_Mahan_common.cpp
clean:
	if [ -f Kamke_Kranich_Mahan_server.out ]; then rm server.out; fi
	if [ -f Kamke_Kranich_Mahan_client.out ]; then rm client.out; fi
to_poseidon:
	scp *.[hc++] makefile ${UWECID}@poseidon0.cs.uwec.edu:/USERS/ALL/${UWECID}/${POSEIDONWD}
from_poseidon:
	scp ${UWECID}@poseidon0.cs.uwec.edu:/USERS/ALL/${UWECID}/${POSEIDONWD}/*.[hc++] .

run_client:
	./client.out
run_server:
	./server.out