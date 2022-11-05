/* */
/* Filename : packet_struct.h */
/* Team :  */
/* */

#ifndef CS_462_PROJECT_PACKET_STRUCT_H
#define CS_462_PROJECT_PACKET_STRUCT_H

// first 2 indices of each packet are for the sequence number, so data starts at index 2
#define START_DATA_INDEX 2
//wrapper size is the # of bytes of the sequence number + the crc
#define WRAPPER_SIZE 6


#include <iostream>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "common.h"

class packetClass {
public:
    uint16_t sequenceNumber;
    char buffer[MAX_BUF_SIZE];
    bool sent;
    bool ack;
    int packet_bytes_read;
    uint32_t CRC;
    bool used;


    void freeUp() {
        used = false;
        sequenceNumber = 0;
        sent = false;
        ack = false;
        packet_bytes_read = 0;
        CRC = 0;
        bzero(buffer, MAX_BUF_SIZE);
    }

    bool isUsed() {
        return used;
    }



    void loadPacket(uint16_t sn, int pbr, char *writeData) {
        sent = false;
        ack = false;
        sequenceNumber = sn;
        packet_bytes_read = pbr;
        used = true;
        memcpy(&buffer[START_DATA_INDEX], writeData, pbr);
        BreakINT16(buffer, sequenceNumber);
        CRC = crcFun((uint8_t *) buffer, packet_bytes_read + START_DATA_INDEX);
        BreakINT32(&buffer[packet_bytes_read + START_DATA_INDEX], CRC);
    }

    char *getBuffPoint() {
        return buffer;
    }

    uint16_t getSN() {
        return sequenceNumber;
    }

    void setSN(uint16_t sequenceNum) {
        sequenceNumber = sequenceNum;
        BreakINT16(buffer, sequenceNumber);
        CRC = crcFun((uint8_t *) buffer, packet_bytes_read + START_DATA_INDEX);
        BreakINT32(&buffer[packet_bytes_read + START_DATA_INDEX], CRC);
    }

    bool getSent() {
        return sent;
    }

    void setSent(bool s) {
        sent = s;
    }

    bool getAck() {
        return ack;
    }

    void setAck(bool a) {
        ack = a;
    }

    void updateCRC(uint32_t crc) {
        CRC = crc;
        BreakINT32(&buffer[packet_bytes_read + START_DATA_INDEX], CRC);
    }



};


#endif //CS_462_PROJECT_PACKET_STRUCT_H
