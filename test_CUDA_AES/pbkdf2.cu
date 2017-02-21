

#include "pbk_common.h"
#include <stdio.h>
//#include "/usr/local/cuda-sdk/C/common/inc/cutil.h"
#include <errno.h>

#define PASS 8 //needs to be devisible by 4. if not then pad
#define HLEN 20
__device__ void ThreadToPass(unsigned int num, char * pass) {
  //assume we just work with numbers
  //we know we have max 9 numbers because of the size of int
 /* int temp = num % 10;
  pass[7] = (char) temp + 48;
  temp = (num % 100) / 10; //remember C always rounds down
  pass[6] = (char) temp + 48;
  temp = (num % 1000) / 100;
  pass[5] = (char) temp + 48;
  temp = (num % 10000) / 1000;
  pass[4] = (char) temp + 48;
  temp = (num % 100000) / 10000;
  pass[3] = (char) temp + 48;
  temp = (num % 1000000) / 100000;
  pass[2] = (char) temp + 48;
  temp = (num % 10000000) / 1000000;
  pass[1] = (char) temp + 48;
  temp = (num % 100000000) / 10000000;
  pass[0] = (char) temp + 48;

  //remove the leasing zeros, equivilent to trim
  int zeros = 0;
  for (int i = 0; i <= 7 && pass[i] == '0'; i++) {
    zeros++;
  }
  for (int i = 0; i <=7; i++) {
    if (i >= 8 - zeros) //set null chars
      if (i == 0)
	pass[i] = '0'; //if we try to encode the number 0
      else
	pass[i] = '\0';
    else
      pass[i] = pass[zeros+i];
  }*/
   pass[7]='w';
   pass[6]='o';
   pass[5]='r';
   pass[4]='d';
   pass[3]='d';
   pass[2]='d';
   pass[1]='d';
   pass[0]='d';
}

__device__ void F (size_t hLen,
		   const void * passwordPtr, size_t passwordLen,
		   const void * saltPtr, size_t saltLen,
		   size_t iterationCount,
		   size_t blockNumber,
		   void *dataPtr, size_t dkLen,
		   void *tempBuffer,
		   struct globalChars *chars)
{

  uint8_t *inBlock, *outBlock, *resultBlockPtr;
  size_t iteration;
  outBlock = (uint8_t*) tempBuffer;
  inBlock = outBlock + hLen;
  /* Set up inBlock to contain Salt || INT (blockNumber). */
  cudaMemcpyDevice(inBlock, saltPtr, saltLen);

  ((uint32_t *) inBlock)[saltLen/4] = SWAP(blockNumber);

  // Caculate U1 (result goes to outBlock) and copy it to resultBlockPtr.
  resultBlockPtr = (uint8_t*) dataPtr;
  hmac_sha1 (passwordPtr, passwordLen, inBlock, saltLen + 4, outBlock, chars);
  cudaMemcpyDevice(resultBlockPtr, outBlock, hLen);
  // Calculate U2 though UiterationCount.
  for (iteration = 2; iteration <= iterationCount; iteration++)
    {
      uint8_t *tempBlock;
      size_t byte;
      // Swap inBlock and outBlock pointers.
      tempBlock = inBlock;
      inBlock = outBlock;
      outBlock = tempBlock;
      // Now inBlock conatins Uiteration-1.  Calclulate Uiteration into outBlock.
      hmac_sha1 (passwordPtr, passwordLen, inBlock, hLen, outBlock, chars);
      // Xor data in dataPtr (U1 \xor U2 \xor ... \xor Uiteration-1) with
      // outBlock (Uiteration).
      for (byte = 0; byte < hLen/4; byte++) {
	((uint32_t*)resultBlockPtr)[byte] ^= ((uint32_t*)outBlock)[byte];
      }
    }
}

__global__ void pbkdf2 (size_t passwordLen,
			const void * saltPtr, size_t saltLen,
			size_t iterationCount,
			uint8_t* dkPtr,
			size_t dkLen)
{
  __shared__ uint8_t sharedData[BLOCK_DIM][HLEN];
  __shared__ uint8_t sharedTemp[BLOCK_DIM][2*HLEN];
  __shared__ uint8_t sharedPass[BLOCK_DIM][PASS];
  __shared__ struct globalChars sharedChars[BLOCK_DIM];

  int num = blockIdx.x*blockDim.x + threadIdx.x;
  ThreadToPass(num, (char*)sharedPass[threadIdx.x]);
  __syncthreads();

  size_t completeBlocks;
  //completeBlocks = dkLen / HLEN;
  completeBlocks=dkLen;
  size_t partialBlockSize;
  partialBlockSize = dkLen % HLEN;

  if (completeBlocks == 1) {
    F (HLEN, sharedPass[threadIdx.x], passwordLen, (uint8_t*)saltPtr, saltLen,
       iterationCount, 1, sharedData[threadIdx.x], dkLen,sharedTemp[threadIdx.x], &sharedChars[threadIdx.x]);
  } else {
    // Handle handle the case if partialBlockSize > 0 or if the password is longer than 20 bytes
  }
  __syncthreads();
  size_t gridSize = (size_t) ceil((float)TEST_SIZE / (float)BLOCK_DIM);
  //final block
  if (blockIdx.x == gridSize-1){
    for (int r = 0; r < HLEN; ++r) {
      dkPtr[BLOCK_DIM*threadIdx.x+r] = sharedData[threadIdx.x][r];
    }
  }
  __syncthreads();
}


extern "C" __host__
void doIt( uint32_t iterationCount) {
  clock_t t0, t1;
  //hLen is length of prf output in bytes, for sha1 it is 160 bit = 20 bytes
  size_t hLen = HLEN;
  size_t passwordLen = PASS;
  //password should be a byte string, ie string consisting of characters of 8 bits
  const unsigned int block_dim_x = BLOCK_DIM;// 64; //max threads pr block
  size_t saltLen = 6;
  // TempBuffer should be of size hLen
  //changed for our SSID
  char * salt = "ATT256";
  //Length of result key in bytes, most be less than 2^32 * hLen
  size_t dkLen = 32; //hardcoded in our case
  //dKPtr is where the resultant key is stored, also as a byte string
  //aes = 128, 192, 256 bits, ie 16, 24, 32 bytes
  uint8_t* dkPtr;
  void * saltPtr;
  //Each 20 byte value needs 32 bytes to make cudamemcpy happy
  uint8_t * data= (uint8_t* ) malloc(BLOCK_DIM*32);
  double datetime_diff_ms = 0;

  for (int i =1; i<= 1; i++) {
    //Sync to avoid async timing
    cudaDeviceSynchronize();
    t0 = clock();

//    CUDA_SAFE_CALL(cudaMalloc(&dkPtr, BLOCK_DIM*32));
    cudaMalloc(&dkPtr, BLOCK_DIM*32);

    //only read, no need to be of size 32
//    CUDA_SAFE_CALL(cudaMalloc(&saltPtr, saltLen));
//    CUDA_SAFE_CALL(cudaMemcpy(saltPtr, salt, saltLen, cudaMemcpyHostToDevice));
    cudaMalloc(&saltPtr, saltLen);
    cudaMemcpy(saltPtr, salt, saltLen, cudaMemcpyHostToDevice);

    size_t gridSize = (size_t) ceil((float)TEST_SIZE / (float)block_dim_x);
    dim3 block(block_dim_x, 1, 1);
    dim3 grid(gridSize,1,1);
    //first amount of rows

    pbkdf2<<< gridSize, block>>>(passwordLen, saltPtr, saltLen, iterationCount, dkPtr, dkLen);

//    CUDA_SAFE_CALL(cudaMemcpy(data, dkPtr, BLOCK_DIM*32, cudaMemcpyDeviceToHost));
    cudaMemcpy(data, dkPtr, BLOCK_DIM*32, cudaMemcpyDeviceToHost);

    cudaFree(saltPtr);
    cudaFree(dkPtr);

    //Sync to avoid async timing
    cudaDeviceSynchronize();
    cudaDeviceReset();
    t1 = clock();

    datetime_diff_ms += difftime(t1, t0)  / CLOCKS_PER_SEC;
    printf("time diff is %d\n", datetime_diff_ms);
  }

  for (int k =0; k<block_dim_x; k++) {
    for (int j =0; j< hLen ; j++) {
      printf("%x",data[k*block_dim_x+j]);
    }
    printf("\n");
  }
  free(data);
}
int main(void)
{
  printf("starting..\n");
  uint32_t iterations =  (uint32_t)4096;
  doIt(iterations);
}
/**
static size_t correctMalloc(size_t input) {
   size_t temp = input;
      size_t add;
      if (temp % 4 != 0) {
      add = 4 -(temp % 4);
      temp += add;
      }
      input = temp;
  return input;
}*/

void Check_CUDA_Error(const char *message)
{
  if (errno != 0) {
    printf("C Error: %s: %s\n", message, strerror( errno ));
    //exit(-1);
  }
  cudaError_t error = cudaGetLastError();
  if(error!=cudaSuccess) {
    fprintf(stderr,"CUDA ERROR: %s: %s\n", message, cudaGetErrorString(error) );
    exit(-1);
  }
}

__forceinline__ __device__
void cudaCorrectMalloc(size_t *input) {
  /* size_t temp = *input;
     size_t add;
     if (temp % 4 != 0) {
     add = 4-(temp % 4);
     temp += add;
     }
     *input = temp;*/
}
