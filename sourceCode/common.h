/* */
/* Filename : common.h */
/* Team :  */
/* */

#ifndef CS_462_PROJECT_COMMON_H
#define CS_462_PROJECT_COMMON_H

#define ACK 0x06
#define NAK 0x15
#define SHOW_BUFFER 0
#define SHOW_ENTIRE_PACKET 0
#define MAX_WINDOW_SIZE 25
#define DEFAULT_TIMEOUT_US 50000
#define MAX_PACKET_SIZE 10000
#define MAX_BUF_SIZE (MAX_PACKET_SIZE * 5) // may need to change this if we don't have room for the crc
                           // (since it takes up 4 indices instead of 2 now)
#define DEBUGCRC 0


/* CRC generation code is modified from Michael Barr's open source code:
 *  https://barrgroup.com/Embedded-Systems/How-To/CRC-Calculation-C-Code
 */
typedef unsigned int crc;


#define CRC_NAME "CRC-32"
#define POLYNOMIAL 0x04C11DB7
#define INITIAL_REMAINDER 0xFFFFFFFF
//#define FINAL_XOR_VALUE 0xFFFFFFFF // might need this if CHECK_VALUE doesn't match
#define CHECK_VALUE 0xCBF43926
#define CRCBYTES sizeof(crc)

void crcTableInit();
crc crcFun(unsigned char const message[], int nBytes);


//error
void error_and_exit(std::ostream& log, const char *msg);

// user input prompts
int slidingWindowSizePrompt(int defaultWindowSize);
int situationalErrorsPrompt(int defaultSituationalErrors);
int portNumPrompt(int defaultPortNum);
std::string filePathPrompt(std::string defaultPath);
std::string ipAddressPrompt(std::string defaultIpAddress);
int protocolTypePrompt(int defaultProtocol);
int packetSizePrompt(int defaultPacketSize);
int timeoutIntervalPrompt();
int rangeOfSequenceNumbersPrompt(int defaultWinSize);
int isInSlidingWindow(uint16_t, uint16_t, int slidingWindowSize, int rangeOfSequenceNumbers);
int isInPreviousWindow(uint16_t sn, uint16_t recsn, int slidingWindowSize);


// display/log output
void displayMessage(std::ostream& console, std::ostream& log, std::string mess);
void displayIntDataMessage(std::ostream& console, std::ostream& log, std::string pre, int data, std::string post);
void displayDoubleDataMessage(std::ostream &console, std::ostream &log, std::string pre, double data, std::string post);
void displayBuffer(std::ostream& console, std::ostream& log, char *buf, int num_bytes);
void displayEntirePacket(std::ostream &console, std::ostream &log, char *buf, int num_bytes);
void printWindow(std::ostream& console, std::ostream& log, int slidingWS, int seq, int rangeOfSeqNum);

char *GetTimeStamp(char *timeStamp);

int16_t MakeINT16(char buff[]);
void BreakINT16(char buff[], int16_t i);

int32_t MakeINT32(char buff[]);
void BreakINT32(char buff[], int32_t i);




/*
 * CRC generation code is copied from the Modbus specification.
 * NOT USED ANYMORE, KEPT FOR EMERGENCIES
 */
/*/
uint16_t crc16(uint8_t *data, int len);
//*/

#endif //CS_462_PROJECT_COMMON_H
