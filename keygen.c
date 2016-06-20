/*********************************************************************
 ** Program Filename: keygen.c 
 ** Author: Peter Nguyen
 ** Date: 3/14/16
 ** CS 344-400, Program 4
 ** Description: Outputs a key file of specified length
 *********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

const int ASCII_A = 65;
const int ASCII_Z = 90;

int main(int argc, char* argv[])
{
  int keyLength;
  int randChar;

  // Get key length from argv, else print error message
  if (argc < 2)
    printf("error: key length must be specified\n");
  else
  {
    keyLength = atoi(argv[1]);
  }

  // Generate random char from 'A' to 'Z' + 1 (65 to 91)
  srand(time(NULL));
  int i;
  for (i = 0; i < keyLength; i++)
  {
    randChar = rand() % (ASCII_Z + 2 - ASCII_A) + ASCII_A;
    if (randChar == (ASCII_Z + 1)) // generate space if char is 'Z' + 1
      printf(" ");
    else
      printf("%c", randChar);
  }
  printf("\n");
 
  return 0;
}

