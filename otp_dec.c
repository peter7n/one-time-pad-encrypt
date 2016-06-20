/*********************************************************************
 ** Program Filename: otp_dec.c
 ** Author: Peter Nguyen
 ** Date: 3/14/16
 ** CS 344-400, Program 4
 ** Description: Sends ciphertext and key to otp_dec_d and receives
 ** back the decrypted text.
 *********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

const int BUFF_SIZE = 70000;

// Function prototypes
void error(const char *msg);
void writeSock(int sockfd, char* buffer);
void readSock(int sockfd, char* buffer, int size);
int validChars(char* buffer);

int main(int argc, char *argv[])
{
  int sockfd,
      portno,
      n,
      receivedNum = 0, // int representing the data size sent
      returnStatus,    // value returned from read or write
      dataSizeNum,
      convertedNum,
      connectStatus;
  struct sockaddr_in serv_addr;
  struct hostent *server;        // Defines a host computer
  char txtBuffer[BUFF_SIZE],
       keyBuffer[BUFF_SIZE],
       plainBuffer[BUFF_SIZE];
  FILE* filePtr;

  // Check for correct arguments
  if (argc < 4)
  {
    fprintf(stderr,"usage: %s ciphertext key port\n", argv[0]);
    exit(0);
  }

  // Read the ciphertext file
  filePtr = fopen(argv[1], "r");
  if (filePtr == NULL)
  {
    fprintf(stderr, "could not open ciphertext file\n");
    exit(1);
  }
  bzero(txtBuffer, BUFF_SIZE);
  fgets(txtBuffer, BUFF_SIZE, filePtr);
  fclose(filePtr);

  // Read the key file
  filePtr = fopen(argv[2], "r");
  if (filePtr == NULL)
  {
    fprintf(stderr, "could not open key file\n");
    exit(1);
  }
  bzero(keyBuffer, BUFF_SIZE);
  fgets(keyBuffer, BUFF_SIZE, filePtr);
  fclose(filePtr);

  // Check for bad characters or if key file is too short
  if (strlen(keyBuffer) < strlen(txtBuffer))
  {
    fprintf(stderr, "ERROR: key %s is too short\n", argv[2]);
    exit(1);
  }

  if (!validChars(txtBuffer))
  {
    fprintf(stderr, "ERROR: bad characters in %s\n", argv[1]);
    exit(1);
  }
  if (!validChars(keyBuffer))
  {
    fprintf(stderr, "ERROR: bad characters in %s\n", argv[2]);
    exit(1);
  }

  /******** Connect to server ********/

  // Set port number and host name
  portno = atoi(argv[3]);
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    error("ERROR opening socket");
  server = gethostbyname("localhost");
  if (server == NULL)
  {
    fprintf(stderr,"ERROR, no such host\n");
    exit(1);
  }

  // Set server address
  bzero((char *) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  bcopy((char *)server->h_addr,
        (char *)&serv_addr.sin_addr.s_addr,
        server->h_length);
  serv_addr.sin_port = htons(portno);

  // Connect to the server
  if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    error("ERROR connecting");

  // Check if trying to connect to otp_enc_d; if so, reject
  returnStatus = read(sockfd, &receivedNum, sizeof(receivedNum));
  if (returnStatus > 0)
  {
    receivedNum = ntohl(receivedNum);
    if (receivedNum == 1)
    {
      fprintf(stderr, "ERROR: could not contact otp_enc_d on port %s\n",
              argv[3]);
      exit(2);
    }
  }

  // Receive the new port number from server after initial connect
  returnStatus = read(sockfd, &receivedNum, sizeof(receivedNum));
  if (returnStatus > 0)
    receivedNum = ntohl(receivedNum);
  else
    fprintf(stderr, "ERROR receiving port number: %d\n", returnStatus);

  // Restart socket on new port number

  close(sockfd);
  // Set port number and host name
  portno = receivedNum; // set to new port number
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    error("ERROR opening socket");
  server = gethostbyname("localhost");
  if (server == NULL)
  {
    fprintf(stderr,"ERROR, no such host\n");
    exit(0);
  }
  // Set server address
  bzero((char *) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  bcopy((char *)server->h_addr,
        (char *)&serv_addr.sin_addr.s_addr,
        server->h_length);
  serv_addr.sin_port = htons(portno);
  // Connect to the server
  do
  {
  connectStatus =
    connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
  if (connectStatus < 0)
    perror("ERROR connecting");
  } while (connectStatus < 0);

  /******** Begin data exchange with server *********/

  // Write the data size of ciphertext to the socket
  dataSizeNum = strlen(txtBuffer);
  convertedNum = htonl(dataSizeNum);
  returnStatus = write(sockfd, &convertedNum, sizeof(convertedNum));
  if (returnStatus < 0)
    error("ERROR writing data size");
  // Write ciphertext to the socket
  writeSock(sockfd, txtBuffer);

  // Write the data size of the key to the socket
  dataSizeNum = strlen(keyBuffer);
  convertedNum = htonl(dataSizeNum);
  returnStatus = write(sockfd, &convertedNum, sizeof(convertedNum));
  if (returnStatus < 0)
    error("ERROR writing data size");
  // Write key to the socket
  writeSock(sockfd, keyBuffer);

  // Read the data size of plaintext
  returnStatus = read(sockfd, &receivedNum, sizeof(receivedNum));
  if (returnStatus > 0)
    receivedNum = ntohl(receivedNum);
  else
    fprintf(stderr, "ERROR receiving data size: %d\n", returnStatus);
  // Read plaintext from the socket
  readSock(sockfd, plainBuffer, receivedNum);

  printf("%s", plainBuffer);

  close(sockfd);
  return 0;
}

/*********************************************************************
 ** writeSock
 ** Description: Writes data to the specified socket from the
 ** specified buffer in "chunks" of 1000 bytes.
 ** Parameters: int sockfd, char* buffer
 *********************************************************************/
void writeSock(int sockfd, char* buffer)
{
  int bytesWrit,
      totalBytesWrit = 0,
      index,
      tempIndex;
  char tempBuffer[BUFF_SIZE];

  bytesWrit = write(sockfd, buffer, strlen(buffer));

  if (bytesWrit < 0)
    error("ERROR writing to socket");
  else if (bytesWrit < strlen(buffer))
  {
    // Continue to write until all data has been sent
    while (totalBytesWrit != strlen(buffer))
    {
      totalBytesWrit += bytesWrit;
      index = totalBytesWrit + 1;
      tempIndex = 0;
      do
      // Copy remaining data to be written until temp buffer
      {
        tempBuffer[tempIndex] = buffer[index];
        index++;
        tempIndex++;
      } while (buffer[index] != '\0');

      bytesWrit = write(sockfd, tempBuffer, strlen(tempBuffer));
    }
  }
}

/*********************************************************************
 ** readSock
 ** Description: Reads data from the specified socket to the specified
 ** buffer. Takes the total data size to be read as a parameter
 ** Parameters: int sockfd, char* buffer, int size
 *********************************************************************/
void readSock(int sockfd, char* buffer, int size)
{
  char tempBuffer[BUFF_SIZE];
  int bytesRead;

  bzero(buffer, BUFF_SIZE);
  do
  {
    bzero(tempBuffer, BUFF_SIZE);
    // Continue reading into temp buffer until buffer length = size
    bytesRead = read(sockfd, tempBuffer, size);
    if (bytesRead < 0)
      error("ERROR reading from socket");

    strcat(buffer, tempBuffer);
  }
  while (strlen(buffer) != size);
}

/*********************************************************************
 ** validChars
 ** Description: Checks string buffer for valid input, i.e.
 ** 'A' through 'Z' or space. Returns true or false.
 ** Parameters: char* buffer
 *********************************************************************/
int validChars(char* buffer)
{
  int index = 0;

  while (buffer[index] != '\0')
  {
    if (buffer[index] < 'A' || buffer[index] > 'Z')
    {
     if (buffer[index] != ' ' && buffer[index] != '\n')
       return 0;  // false: chars are bad
    }
    index++;
  }
  return 1;       // true: chars are valid
}

/*********************************************************************
 ** error
 ** Description: Displays an error message
 ** Parameters: const char *msg
 *********************************************************************/
void error(const char *msg)
{
  perror(msg);
  exit(0);
}
