/* */
/* Filename : common.h */
/* Team :  */
/* */

#ifndef CS_462_PROJECT_COMMON_H
#define CS_462_PROJECT_COMMON_H

#define ACK 0x06
#define NAK 0x15
#define SHOW_BUFFER 0
#define MAX_WINDOW_SIZE 25
#define DEFAULT_TIMEOUT_US 1000
#define MAX_BUF_SIZE 11000 // may need to change this if we don't have room for the crc
                           // (since it takes up 4 indices instead of 2 now)


/* CRC generation code is modified from Michael Barr's open source code:
 *  https://barrgroup.com/Embedded-Systems/How-To/CRC-Calculation-C-Code
 */ 
typedef unsigned int crc;

#define CRC_NAME "CRC-32"
#define POLYNOMIAL 0x04C11DB7
#define INITIAL_REMAINDER 0xFFFFFFFF
//#define FINAL_XOR_VALUE 0xFFFFFFFF // might need this if CHECK_VALUE doesn't match
#define CHECK_VALUE 0xCBF43926

void crcTableInit();
crc crcFun(unsigned char const message[], int nBytes);


//error
void error_and_exit(std::ostream& log, const char *msg);

// user input prompts
int slidingWindowSizePrompt();
int situationalErrorsPrompt();
int portNumPrompt();
std::string filePathPrompt();
std::string ipAddressPrompt();
int protocolTypePrompt();
int packetSizePrompt();
int timeoutIntervalPrompt();
int rangeOfSequenceNumbersPrompt(int);

// diplay/log output
void displayMessage(std::ostream& console, std::ostream& log, std::string mess);
void displayIntDataMessage(std::ostream& console, std::ostream& log, std::string pre, int data, std::string post);
void displayDoubleDataMessage(std::ostream &console, std::ostream &log, std::string pre, double data, std::string post);
void displayBuffer(std::ostream& console, std::ostream& log, char *buf, int num_bytes);
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
