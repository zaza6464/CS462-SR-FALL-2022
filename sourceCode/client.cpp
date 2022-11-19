/* CS-462 Project : Implementation of Sliding Windows Protocol for efficient file transfer. */
/* */
/* Starting with a minimal client shell in the internet domain (https://www.linuxhowtos.org/C_C++/socket.htm) */
/* */
/* This is the CLIENT (which opens the file and sends the data in packets based on 3 protocols). */
/* */
/* Complile with this command: g++ -o client.out client.cpp common.cpp -std=c++11 */
/* */
/* Filename : client.cpp */
/* Team :  Kranich*/
/* */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <string>
#include <fstream>
#include <chrono>
#include "client.h"
#include "common.h"
#include "packet_struct.h"


std::chrono::steady_clock::time_point start_test_ticks;
std::chrono::steady_clock::time_point end_test_ticks;
clock_t start_packet_ticks;
clock_t end_packet_ticks;
time_t myTime;
std::ofstream logFile;
//create ifstream object
std::ifstream fileInputStream;
// Data for sockets
int sock;
int num_bytes = 0;
int packet_bytes_read;
uint32_t sendCheckSum;
uint32_t receiveCheckSum;
uint16_t sequenceNum = 0;
uint16_t nextSeqNum = 0;
uint16_t lastSeqNum = 0;

int outOfOrders = 0;
int packets_sent = 0;
int packets_failed = 0;
int originalPackets = 0;
int retransmittedPackets = 0;
long int totalBytesRead = 0;
long int totalBytesSent = 0;
unsigned int length;
struct sockaddr_in client;
struct sockaddr_in from;
struct hostent *hp;
// Get a large buffer to read file data into
char buffer[MAX_BUF_SIZE];
char rec_buffer[MAX_BUF_SIZE];
// User supplied variables
std::string filePath = "/data/users/kranicac1696/src/1M"; //path to file to be sent
std::string ipAddress = "172.23.0.3"; //IP address of the target server
int portNum = 6789; //port number of the target server
int timeoutIntervalus = DEFAULT_TIMEOUT_US; //user-specified (0+) or ping calculated (-1)
int socketTimeoutus = 1000;  // was 50000 (1G takes 3 hrs with 10% timeouts), was 5000 (1G takes just under 2 hrs with 10% timeouts)
int protocolType = 0; //0 for S&W, 1 for GBN, 2 for SR
int packetSize = 100; //specified size of packets to be sent
int slidingWindowSize = 5; //ex. [1, 2, 3, 4, 5, 6, 7, 8], size = 8
int rangeOfSequenceNumbers = 11; //ex. (sliding window size = 3) [1, 2, 3] -> [2, 3, 4] -> [3, 4, 5], range = 5
int situationalErrors = 0; //none (0), randomly generated (1), or user-specified (2)
int readNewData = 1;
int numPacketsToRead = slidingWindowSize;
int numPacketsToRetransmit = slidingWindowSize;
int at_end_of_file = 0;
bool simulateLost = false;
bool gotLastAck = false;
//char test[12] = {0,0,'t','h','i','s',' ','i','s',' ','a','n'};

packetClass packets[MAX_WINDOW_SIZE];

int main(int argc, char *argv[]) {

    // create the CRC lookup table so we can use it later.
    crcTableInit();

    //crc testcrc = crcFun((uint8_t *)test, 12);
    //std::cout << "the crc of our test string is: " << testcrc << std::endl;

    for (int i = 0; i < slidingWindowSize; i++) {
        packets[i].freeUp();
    }

    //prompt user for each of the following fields
    //ipAddress = ipAddressPrompt(ipAddress);
    //portNum = portNumPrompt(portNum);
    packetSize = packetSizePrompt(packetSize);
    //timeoutIntervalus = timeoutIntervalPrompt();

    protocolType = protocolTypePrompt(protocolType);

    if (protocolType != 0) {
        slidingWindowSize = slidingWindowSizePrompt(slidingWindowSize);
    } else {
        slidingWindowSize = 1;
    }
    numPacketsToRead = slidingWindowSize;
    //rangeOfSequenceNumbers = rangeOfSequenceNumbersPrompt(slidingWindowSize);


    //situationalErrors = situationalErrorsPrompt(situationalErrors);

    filePath = "/data/users/kranicac1696/src/" + filePathPrompt(filePath);



    //open file at filepath in read and binary modes
    fileInputStream.open(filePath, std::ios_base::in | std::ios_base::binary);
    if (!fileInputStream.is_open()) {
        error_and_exit(logFile, "Read file not opened successfully!!");
    }

    //create a stream to the log file

    logFile.open("output/client_log.log", std::ios_base::in | std::ios_base::app);
    if (!logFile.is_open()) {
        error_and_exit(logFile, "Log file not opened successfully!!");
    }

    //navigate to section of file beginning at (sequenceNumber * packetSize) offset from beginning
    //std::cout << "halfway through writefile" << std::endl;


//  set global packet struct sequence number
//  myPacket.sequenceNumber = sequenceNumber;
//  clear the current contents of the global packet struct char vector
//  myPacket.contents.clear();
//  copy the contents of the array to the global packet struct char vector
//  std::copy(&contents[0], &contents[packetSize], back_inserter(myPacket.contents));
//  fileInputStream.close();
//  std::cout << "end of writefile" << std::endl;


    // First, just make sure we can create the socket
    //sock = socket(AF_INET, SOCK_DGRAM, 0);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) error_and_exit(logFile, "Exit, failed to create socket.");
    bzero(&client, sizeof(client));

    // Next, check that we can "see" the host ipaddress (by name or ipv4 xxx.xxx.xxx.xxx numbers)
    client.sin_family = AF_INET;
    hp = gethostbyname(ipAddress.c_str());
    if (hp == 0) error_and_exit(logFile, "Exit, Couldn't find Server/Host");

    // Set the port number the server is expecting data on.
    bcopy((char *) hp->h_addr, (char *) &client.sin_addr, hp->h_length);
    client.sin_port = htons(portNum);

    length = sizeof(struct sockaddr_in);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = socketTimeoutus;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *) &tv, sizeof tv);

    if (connect(sock, (struct sockaddr *) &client, sizeof(client)) != 0) {
        error_and_exit(logFile, "Connection with server failed, exiting client");
    }

    //fcntl(sock, F_SETFL, O_NONBLOCK);
    // For testing, get user input and store it in the buffer.
    //printf("Enter a string to send to the server for testing:\r\n");
    //bzero(buffer, 256);
    //fgets(buffer, 255, stdin);


    start_test_ticks = std::chrono::steady_clock::now();


    myTime = time(NULL);


    displayMessage(std::cout, logFile, "******************** START OF NEW TEST ********************");
    displayMessage(std::cout, logFile, ctime(&myTime));
    if (protocolType == 0) {
        displayMessage(std::cout, logFile, "Protocol Type: Stop and Wait");
    } else if (protocolType == 1) {
        displayMessage(std::cout, logFile, "Protocol Type: Go-Back-N");
    } else if (protocolType == 2) {
        displayMessage(std::cout, logFile, "Protocol Type: Selective Repeat");
    }
    displayIntDataMessage(std::cout, logFile, "Packet Size: ", packetSize, "");
    displayIntDataMessage(std::cout, logFile, "Timeout Interval: ", timeoutIntervalus, "");
    displayIntDataMessage(std::cout, logFile, "Range of Sequence Numbers: ", rangeOfSequenceNumbers, "");
    displayIntDataMessage(std::cout, logFile, "Window Size: ", slidingWindowSize, "");
    if (situationalErrors == 0) {
        displayMessage(std::cout, logFile, "Situational Errors: None");
    } else if (situationalErrors == 1) {
        displayMessage(std::cout, logFile, "Situational Errors: Randomly Generated");
    } else if (situationalErrors == 2) {
        displayMessage(std::cout, logFile, "Situational Errors: User Generated");
    }


    while (!at_end_of_file || !gotLastAck) {
        // while (!at_end_of_file) {
        
        if (at_end_of_file) std::cout << "at_end_of_file is TRUE" << std::endl;
        if (gotLastAck) std::cout << "gotLastAck is TRUE" << std::endl;
        
        switch (protocolType) {
            case 0:
                // executeSAWProtocol();
                // break;
            case 1:
                executeGBNProtocol();
                break;
            case 2:
                executeSRProtocol();
                break;
            default:
                error_and_exit(logFile, "Exit, Invalid protocol type!");
                break;
        }
    }

    doDoneStuff();
    return 0;
}


/*
void executeSAWProtocol(void) {
    if (readNewData) {
        bzero(buffer, MAX_BUF_SIZE);
        fileInputStream.read(&buffer[START_DATA_INDEX], packetSize);
        packet_bytes_read = fileInputStream.gcount();
        totalBytesRead += packet_bytes_read;
        originalPackets++;
        displayBuffer(std::cout, logFile, &buffer[START_DATA_INDEX], packet_bytes_read);
        if (packet_bytes_read == -1) {
            error_and_exit("Could not open file for reading");
        } else if (packet_bytes_read < packetSize) {
            //We know we must have read the last bit of data
            at_end_of_file = 1;
        }
    }


//        //inserting sequence # into buffer
//        BreakINT16(buffer, sequenceNum);
    printWindow(std::cout, logFile, slidingWindowSize, sequenceNum);

    // Add the seq num and crc to the buffer to send
    BreakINT16(buffer, sequenceNum);
    uint16_t CRC = crc16((uint8_t *) buffer, packet_bytes_read + START_DATA_INDEX);
    BreakINT16(&buffer[packet_bytes_read + START_DATA_INDEX], CRC);

    if (situationalErrors == 1) generateRandomSituationalErrors(buffer, sequenceNum, packet_bytes_read);

    if (simulateLost) {
        // Dont send
        simulateLost = false;
    } else {
        //sending now
        sendto(sock, buffer,
               packet_bytes_read + WRAPPER_SIZE, 0, (const struct sockaddr *) &server, length);
        totalBytesSent += packet_bytes_read + WRAPPER_SIZE;
    }

    DisplayPacketSendMess(sequenceNum);
    displayBuffer(std::cout, logFile, &buffer[START_DATA_INDEX], packet_bytes_read);
    packets_sent++;


    //waiting for response
    num_bytes = recvfrom(sock, rec_buffer, MAX_BUF_SIZE, 0, (struct sockaddr *) &from, &length);

    if (num_bytes < 0) {
//            error_and_exit("recvfrom");
        DisplayPacketTimedout(sequenceNum);
        DisplayPacketRetransMess(sequenceNum);
        readNewData = 0;
        retransmittedPackets++;
    } else if (num_bytes > 0) {
        int16_t receivedSeqNum = MakeINT16(rec_buffer);
        //10% of the time we will simulate not getting an ACK
        if (situationalErrors == 1 && !((packets_sent + rand() % 10 + 1) % 10)) {
//                rec_buffer[START_DATA_INDEX] = NAK;
		}
		if (rec_buffer[START_DATA_INDEX] == ACK) {
			if (sequenceNum == receivedSeqNum) {
				if (at_end_of_file) gotLastAck = true;
				sequenceNum++;
				if (sequenceNum >= rangeOfSequenceNumbers) {
					sequenceNum = 0;
				}
				DisplayAckReceived(receivedSeqNum);
//                        bzero(buffer, MAX_BUF_SIZE);
//                        fileInputStream.read(&buffer[START_DATA_INDEX], packetSize);
//                        packet_bytes_read = fileInputStream.gcount();
//                        totalBytesRead += packet_bytes_read;
                readNewData = 1;
//                        if (packet_bytes_read > 0) {
//                            originalPackets++;
//                            //We know we must have read the last bit of data
//                        } else {
//                            at_end_of_file = 1;
//                        }
                //displayBuffer(std::cout, buffer, packet_bytes_read);
            } else {
                //we are getting an ack for a future or past packet
                //since this isn't what we want we won't do anything
                DisplayPacketRetransMess(sequenceNum);
                retransmittedPackets++;
                outOfOrders++;
                readNewData = 0;
            }
        } else {
            // We should never get a response that isn't an ACK
            DisplayNakReceived(receivedSeqNum);
            DisplayPacketRetransMess(sequenceNum);
            readNewData = 0;
            packets_failed++;
            retransmittedPackets++;
        }

    } else {
        //This has to be the case where num_bytes is 0
        DisplayPacketTimedout(sequenceNum);
        retransmittedPackets++;
        readNewData = 0;
    }

}
*/

void executeGBNProtocol(void) {
//    if (readNewData) {
//        readPacketsFromFile(numPacketsToRead);
//    }
//
//    printWindow(std::cout, logFile, slidingWindowSize, sequenceNum, rangeOfSequenceNumbers);
//
//    //sending now
//    if (sendPackets(numPacketsToRead, sequenceNum) || slidingWindowSize > 1) {
//
//        //waiting for response
//        num_bytes = recvfrom(sock, rec_buffer, MAX_BUF_SIZE, 0, (struct sockaddr *) &from, &length);
//        //num_bytes = recv(sock, rec_buffer, MAX_BUF_SIZE, 0);
//
//        //displayIntDataMessage(std::cout, logFile, "Number of bytes of response:", num_bytes, "");
//        if (num_bytes <= 0) {
//            std::cout << "recv returned with 0 bytes" << std::endl;
//            //WE TIMED OUT!!!!!!!!
//            //crcTableInit();
//
//            DisplayPacketTimedout(sequenceNum);
//            setMarkForRetransmit(sequenceNum, slidingWindowSize);
//
//        } else if (num_bytes > 0) {
//
//            //WE GOT SOME DATA
//            int16_t receivedSeqNum = MakeINT16(rec_buffer);
//
//
//            if (rec_buffer[START_DATA_INDEX] == ACK) {
//
//                DisplayAckReceived(receivedSeqNum);
//
//                int slideFactor = isInSlidingWindow(sequenceNum, receivedSeqNum);
//                std::cout << "Slide Factor: " << slideFactor << std::endl;
//                if (slideFactor > 0) {
//                    //This means we got an ack on our first window so we only shift our window by one
//                    slideWindow(slideFactor, receivedSeqNum);
//
//                    readNewData = 1;
//
//                    if ((at_end_of_file && (receivedSeqNum == lastSeqNum)) || slidingWindowSize == 1) {
//                        gotLastAck = true;
//                    }
//
//                } else {
//                    //we are getting an ack for a future or past packet thats not in our window
//                    //since this isn't what we want we won't do anything
//                    setMarkForRetransmit(sequenceNum, slidingWindowSize);
//                    outOfOrders++;
//                }
//            } else {
//                // We should never get a response that isn't an ACK
//                DisplayNakReceived(receivedSeqNum);
//                setMarkForRetransmit(sequenceNum, slidingWindowSize);
//                packets_failed++;
//            }
//        }
//    } else {
//        std::cout << "in gbn: not sending packet" << std::endl;
//    }
}

void checkAllPacketsForTimeout() {
	int numUsedPackets = 0;
	
    numPacketsToRetransmit = 0;
    for (int i = 0; i < slidingWindowSize; i++) {
        if (packets[i].isUsed()) {
			numUsedPackets++;
            if (packets[i].getSent()) {
                if (!packets[i].getAck()) {
                    //it's used and it's send, we need to check if it's timed out
                    std::chrono::steady_clock::time_point current_ticks = std::chrono::steady_clock::now();
                    double us_elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                            current_ticks - packets[i].getSentTime()).count();
                    if (us_elapsed > timeoutIntervalus) {
                        std::cout << "Packet index for retransmit: " << i << std::endl;
                        DisplayPacketTimedout(packets[i].getSN());
                        setSinglePacketForRetransmit(packets[i].getSN());
                        numPacketsToRetransmit++;
                    }
                    //retransmittedPackets++;
                }
            }
        }
    }
    
    if (numUsedPackets == 0)
    {
		// There are no packets that are waiting to be acked (or even used for that matter)
		gotLastAck = true;
	}
}


void executeSRProtocol(void) {
    if (readNewData) {
        readPacketsFromFile(numPacketsToRead);
    }

    printWindow(std::cout, logFile, slidingWindowSize, sequenceNum, rangeOfSequenceNumbers);
    printQueue(std::cout, logFile, slidingWindowSize, sequenceNum, rangeOfSequenceNumbers);

    readNewData = 0;
    //sending now
    if (sendPackets(numPacketsToRetransmit, sequenceNum) || slidingWindowSize > 1) {

        //waiting for response
        num_bytes = recvfrom(sock, rec_buffer, 3, 0, (struct sockaddr *) &from, &length);


        displayIntDataMessage(std::cout, logFile, "Number of bytes of response:", num_bytes, "");

        displayIntDataMessage(std::cout, logFile, "First two bytes, possible sequence number is: ",
                              MakeINT16(rec_buffer), "");


        if (num_bytes <= 0) {
            //WE TIMED OUT!!!!!!!!
            //crcTableInit();
            //DisplayPacketTimedout(sequenceNum);
            //setMarkForRetransmit(sequenceNum, slidingWindowSize);
            checkAllPacketsForTimeout();
        } else if (num_bytes > 0) {

            if(num_bytes > 3){
                std::cout << "number of bytes: " << num_bytes << " ----EXITING" << std::endl;
                error_and_exit(logFile, "Exiting");
            } else
            {
				displayIntDataMessage(std::cout, logFile, "First two bytes, possible sequence number is: ",
								MakeINT16(rec_buffer), "");
			}
            //WE GOT SOME DATA
            int16_t receivedSeqNum = MakeINT16(rec_buffer);


            if (rec_buffer[START_DATA_INDEX] == ACK) {

                DisplayAckReceived(receivedSeqNum);

                int slideFactor = isInSlidingWindow(sequenceNum, receivedSeqNum, slidingWindowSize,
                                                    rangeOfSequenceNumbers);
                std::cout << "Slide Factor: " << slideFactor << std::endl;
                if (receivedSeqNum == sequenceNum) { //slideFactor == 1) {
                    //This means we got an ack on our first window so we only shift our window by one
                    slideWindow(slideFactor, receivedSeqNum);

                    readNewData = 1;

                    if ((at_end_of_file && (receivedSeqNum == lastSeqNum)) || slidingWindowSize == 1) {
                        gotLastAck = true;
                    }

                } else if (slideFactor > 1) {
                    //we are getting an ack for a future packet that is in our window
                    int index = getPacketIndexBySN(receivedSeqNum);

                    if (index >= 0) {
                        std::cout << "Setting packet index: " << index << " to acked" << std::endl;
                        packets[index].setAck(true);
                    }

                    readNewData = 0;
                    outOfOrders++;
                }

            } else {
                // We should never get a response that isn't an ACK
                DisplayNakReceived(receivedSeqNum);
                setMarkForRetransmit(sequenceNum, slidingWindowSize);
                packets_failed++;
            }
        }
    } else {
        std::cout << "in gbn: not sending packet" <<
                  std::endl;
    }
}

void setMarkForRetransmit(uint16_t seq, int numPackets) {
    int num = 0;
    for (int i = 0; i < numPackets; i++) {

        uint16_t tempSeq = seq + i;
        tempSeq = tempSeq % rangeOfSequenceNumbers;

        int index = getPacketIndexBySN(tempSeq);

        // std::cout << "In setMarkForRetransmit. index : ";
        // std::cout << index;
        // std::cout << std::endl;

        if (index >= 0) {
            if (packets[index].getSent() == true) {
                retransmittedPackets++;
            }
            packets[index].setSent(false);
            DisplayPacketRetransMess(tempSeq);
            num++;
        }
        readNewData = 0;
    }

    numPacketsToRetransmit = num;

}

void setSinglePacketForRetransmit(uint16_t seq) {
    int num = 0;

    int index = getPacketIndexBySN(seq);

    // std::cout << "In setMarkForRetransmit. index : ";
    // std::cout << index;
    // std::cout << std::endl;

    if (index >= 0) {
        if (packets[index].getSent() == true) {
            retransmittedPackets++;
        }
        packets[index].setSent(false);
        DisplayPacketRetransMess(seq);
        num++;
    }
    readNewData = 0;
}


// if this doesn't work, double check START_DATA_INDEX is correct,
// also check to make sure I didn't mess up changing crc from 16 to 32
void generateRandomSituationalErrors(char *buff, uint16_t seq, int bsRead) {
    // Don't do more than one of these errors at a time!

    //10% of the time the packet will be out of order
    // This worked for GBN but not for Selective Repeat.  If we are mutating the sequence number
    // Selective Repeat could accept it as a valid sequence number (if in its window) and store it
    // in the packet queue.  This will corrupt the write file.  For SR, we should maybe NOT mutate the
    // sequence number but instead send some packets from the packet array out of order instead.
    /*if (!(packets_sent % 10)) {
        //inserting sequence # into buffer
        BreakINT16(buff, seq + rand() % 10 + 1);

        // If we mutate the sequence number, we still need a good CRC so recalculate it
        uint32_t CRC = crcFun((uint8_t *) buff, bsRead + START_DATA_INDEX);
        BreakINT32(&buff[bsRead + START_DATA_INDEX], CRC);

    } else */
    if (!((packets_sent + rand() % 10 + 1) % 10)) {
    // if ((originalPackets % 10) == 0) {
        //10% of the time we will send a bad crc
        //inducing bad crc
        uint32_t CRC = rand() % 10 + 1;
        BreakINT32(&buff[bsRead + START_DATA_INDEX], CRC);
    } /*
    // The server also simulates packets lost by just dropping the packet and not sending the ACK.
    else if (!((packets_sent + rand() % 10 + 1) % 10)) {
        //10% the packet will appear to be sent, but will be not actually be send/ it will be lost
        simulateLost = true;
    }
    */
}


int getUnusedPacketIndex() {
    for (int i = 0; i < MAX_WINDOW_SIZE; i++) {
        if (packets[i].isUsed() == false) {
            return i;
        }
    }
    return -1;
}

int getUnsentPacketIndex() {
    for (int i = 0; i < MAX_WINDOW_SIZE; i++) {
        if ((packets[i].isUsed() == true) && (packets[i].getSent() == false)) {
            return i;
        }
    }
    return -1;
}

int getPacketIndexBySN(uint16_t sn) {
    for (int i = 0; i < MAX_WINDOW_SIZE; i++) {
        if ((packets[i].isUsed() == true) && (packets[i].getSN() == sn)) {
            return i;
        }
    }
    return -1;
}

void printQueue(std::ostream &console, std::ostream &log, int slidingWS, int seq, int rangeOfSeqNum) {

    console << "Current queue = [";
    log << "Current queue = [";
    int i = 0;
    for (i = 0; i < slidingWS - 1; i++) {
        console << packets[i].getSN() << ", ";
        log << packets[i].getSN() << ", ";
    }
    console << packets[i].getSN();
    log << packets[i].getSN();
    console << "]" << std::endl;
    log << "]" << std::endl;

}

void readPacketsFromFile(int nPacks) {
    char lBuff[MAX_BUF_SIZE];
    int lBytesRead = 0;

    if (nPacks <= 0 || nPacks > MAX_WINDOW_SIZE) {
        std::cout << "In readPacketsFromFile with invalid nPacks: " << nPacks << std::endl;
        return;
    } else {
        std::cout << "In readPacketsFromFile with nPacks: " << nPacks << std::endl;
    }

    for (int i = 0; i < nPacks; i++) {

        int packIndex = getUnusedPacketIndex();
        if (packIndex > -1) {
            bzero(lBuff, MAX_BUF_SIZE);
            fileInputStream.read(lBuff, packetSize);
            lBytesRead = fileInputStream.gcount();

            if (lBytesRead < 0) error_and_exit(logFile, "Could not open file for reading");

            if (lBytesRead == 0) {
                std::cout << "At end of file in readPacketsFromFile" << std::endl;
                at_end_of_file = 1;
                return;
            } else if (lBytesRead < packetSize) {
                //We know we must have read the last bit of data
                std::cout << "At end of file in readPacketsFromFile" << std::endl;
                at_end_of_file = 1;
            }
            totalBytesRead += lBytesRead;
            originalPackets++;
            packets[packIndex].loadPacket(nextSeqNum, lBytesRead, lBuff);
            std::cout << "packet index: " << packIndex << " nextSeqNum: " << nextSeqNum << std::endl;

            lastSeqNum = nextSeqNum;
            nextSeqNum++;
            nextSeqNum = nextSeqNum % rangeOfSequenceNumbers;


        } else {
            error_and_exit(logFile, "Ran out of packet buffers");
        }
    }
}

bool sendPackets(int nPacks, uint16_t startSN) {
//    std::cout << "In sendPackets. nPacks : ";
//    std::cout << nPacks;
//    std::cout << std::endl;

    bool returnCode = false;
    for (int i = 0; i < slidingWindowSize; i++) {

        uint16_t tempSeq = startSN + i;
        tempSeq = tempSeq % rangeOfSequenceNumbers;

        int packIndex = getPacketIndexBySN(tempSeq);

        // int packIndex = getUnsentPacketIndex();

        if ((packIndex > -1) && (packets[packIndex].getSent() == false)) {
            std::cout << "In sendPackets. nPacks: " << nPacks << std::endl;
            std::cout << "In sendPackets. packIndex: " << packIndex << std::endl;
            std::cout << "In sendPackets. Packet sequenceNum: " << packets[packIndex].getSN() << std::endl;
            std::cout << "packet_bytes_read: " << packets[packIndex].packet_bytes_read << std::endl;

            // use a temporary buffer so original seq num doesn't get permanently changed when we are
            // simulating errors.
            bzero(buffer, MAX_BUF_SIZE);
            memcpy(buffer, packets[packIndex].getBuffPoint(), packets[packIndex].packet_bytes_read + WRAPPER_SIZE);

            if (situationalErrors == 1 && !at_end_of_file) {
                generateRandomSituationalErrors(buffer, packets[packIndex].getSN(),
                                                packets[packIndex].packet_bytes_read);

                // displayBuffer(std::cout, &buffer[START_DATA_INDEX], packets[packIndex].packet_bytes_read);
            }

            if (simulateLost) {
                // Dont send
                simulateLost = false;
            } else {
                //sending now
                std::cout << "In sendPackets, packet bytes read: " << packets[packIndex].packet_bytes_read << std::endl;
                sendto(sock, buffer,
                       packets[packIndex].packet_bytes_read + WRAPPER_SIZE, 0,
                       (const struct sockaddr *) &client, length);
                //write(sock, buffer,packets[packIndex].packet_bytes_read + WRAPPER_SIZE);
                totalBytesSent += packets[packIndex].packet_bytes_read + WRAPPER_SIZE;

                DisplayPacketSendMess(packets[packIndex].getSN());
                displayBuffer(std::cout, logFile, &buffer[START_DATA_INDEX], packets[packIndex].packet_bytes_read);
                displayEntirePacket(std::cout, logFile, &buffer[0],
                                    packets[packIndex].packet_bytes_read + WRAPPER_SIZE);
                packets[packIndex].setSent(true);
                packets[packIndex].startSentTime();
                // gotLastAck = false;
            }
            returnCode = true;
            packets_sent++;
        }
    }

    return returnCode;
}

void slideWindow(int slideFactor, uint16_t recSN) {
    //We are acknowledging 1 or more packets have been acked by accepting the last sequence number
    numPacketsToRead = 0;
    numPacketsToRetransmit = 0;
    for (int i = 0; i < slidingWindowSize; i++) {
        for (int j = 0; j < slidingWindowSize - 1; j++) {
            packets[j] = packets[j + 1];
        }
        packets[slidingWindowSize - 1].freeUp();
        numPacketsToRead++;
        numPacketsToRetransmit++;
        sequenceNum++;
        sequenceNum = sequenceNum % rangeOfSequenceNumbers;

        if (!packets[0].getAck()) {
            break;
        } else {
            std::cout << "In slideWindow, sliding additional packet of sequenceNum: " << packets[0].getSN()
                      << std::endl;
        }
    }
}

//this returns 0 if its not in the window and if it is it returns how many to slide
//int isInSlidingWindow(uint16_t sn, uint16_t recsn) {
//    for (int i = 0; i < slidingWindowSize; i++) {
//        if (recsn == (sn + i) % rangeOfSequenceNumbers) {
//            return i + 1;
//        }
//    }
//    return 0;
//}




void DisplayPacketSendMess(int packetNum) {
    displayIntDataMessage(std::cout, logFile, "Packet ", packetNum, " sent");
}

void DisplayPacketRetransMess(int packetNum) {
    displayIntDataMessage(std::cout, logFile, "Packet ", packetNum, " Re-transmitted");
}

void DisplayAckReceived(int packetNum) {
    displayIntDataMessage(std::cout, logFile, "\r\nAck ", packetNum, " received\r\n");
}

void DisplayNakReceived(int packetNum) {
    displayIntDataMessage(std::cout, logFile, "Nak ", packetNum, " received");
}

void DisplayPacketTimedout(int packetNum) {
    displayIntDataMessage(std::cout, logFile, "Packet ", packetNum, " *****Timed Out *****");
}

void doDoneStuff() {
    std::cout << "In DoDoneStuff" << std::endl;
    //we're done but to be safe we will send command to server to close the file
    //30,000 is a special sequence number close file code
    BreakINT16(buffer, 30000);
    uint32_t CRC = crcFun((uint8_t *) buffer, START_DATA_INDEX);
    BreakINT32(&buffer[START_DATA_INDEX], CRC);
    sendto(sock, buffer,
           WRAPPER_SIZE, 0, (const struct sockaddr *) &client, length);

    // Close socket, inputstream, and exit
    fileInputStream.close();
    close(sock);

    end_test_ticks = std::chrono::steady_clock::now();


    myTime = time(NULL);
    // ctime() used to give the present time

    displayMessage(std::cout, logFile, ctime(&myTime));

    double total_test_us = std::chrono::duration_cast<std::chrono::microseconds>(
            end_test_ticks - start_test_ticks).count();

    displayMessage(std::cout, logFile, "Session Successfully terminated");
    std::cout << std::endl;
    logFile << std::endl;

    displayIntDataMessage(std::cout, logFile, "Number of original packets sent: ", originalPackets, "");

    displayIntDataMessage(std::cout, logFile, "Number of retransmitted packets: ", retransmittedPackets, "");

    displayDoubleDataMessage(std::cout, logFile, "Total elapsed time (ms): ", total_test_us / 1000.0, "");
    displayDoubleDataMessage(std::cout, logFile, "Total throughput (Mbps) : ", (totalBytesSent * 8.0) / total_test_us,
                             "");
    displayDoubleDataMessage(std::cout, logFile, "Effective throughput: ", (totalBytesRead * 8.0) / total_test_us, "");

    displayMessage(std::cout, logFile, "");
    displayMessage(std::cout, logFile, "");
    displayMessage(std::cout, logFile, "");
    displayMessage(std::cout, logFile, "");
    displayMessage(std::cout, logFile, "");

//    std::cout << "Number of out of order acks: ";
//    std::cout << outOfOrders << std::endl;

    logFile.close();
}
