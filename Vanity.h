/*
 * This file is part of the VanitySearch distribution (https://github.com/JeanLucPons/VanitySearch).
 * Copyright (c) 2019 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef VANITYH
#define VANITYH

#include <string>
#include <vector>
#include "SECP256k1.h"
#include "GPU/GPUEngine.h"
#include <atomic>
#ifdef WIN64
#include <Windows.h>
#endif

extern std::atomic<bool> Pause;
extern std::atomic<bool> Paused;
extern int idxcount;
extern double t_Paused;
extern bool randomMode;

class VanitySearch;

#ifdef WIN64
//typedef HANDLE THREAD_HANDLE;
#define LOCK(mutex) WaitForSingleObject(mutex,INFINITE);
#define UNLOCK(mutex) ReleaseMutex(mutex);
#else
//typedef pthread_t THREAD_HANDLE;
#define LOCK(mutex)  pthread_mutex_lock(&(mutex));
#define UNLOCK(mutex) pthread_mutex_unlock(&(mutex));
#endif

typedef struct {

	VanitySearch* obj;
	int  threadId;
	bool isRunning;
	bool hasStarted;
	int  gridSizeX;
	int  gridSizeY;
	int  gpuId;
	Int  THnextKey;

} TH_PARAM;

typedef struct {

	char* address;
	int addressLength;
	address_t sAddress;	
	bool* found;

	// For dreamer ;)
	bool isFull;
	addressl_t lAddress;
	uint8_t hash160[20];

} ADDRESS_ITEM;

typedef struct {

	std::vector<ADDRESS_ITEM>* items;
	bool found;

} ADDRESS_TABLE_ITEM;

typedef struct {

	Int  ksStart;
	Int  ksNext;
	Int  ksFinish;

} BITCRACK_PARAM;

class VanitySearch {

public:

	VanitySearch(Secp256K1* secp, std::vector<std::string>& address, int searchMode,
		bool stop, std::string outputFile, uint32_t maxFound, BITCRACK_PARAM* bc);

	void Search(std::vector<int> gpuId, std::vector<int> gridSize);
	void FindKeyGPU(TH_PARAM* p);

private:

	std::string GetHex(std::vector<unsigned char>& buffer);
	std::string GetExpectedTimeBitCrack(double keyRate, double keyCount, BITCRACK_PARAM* bc);
	bool checkPrivKey(std::string addr, Int& key, int32_t incr, int endomorphism, bool mode);
	void checkAddr(int prefIdx, uint8_t* hash160, Int& key, int32_t incr, int endomorphism, bool mode);
	void checkAddrSSE(uint8_t* h1, uint8_t* h2, uint8_t* h3, uint8_t* h4,
		int32_t incr1, int32_t incr2, int32_t incr3, int32_t incr4,
		Int& key, int endomorphism, bool mode);
	void checkAddresses(bool compressed, Int key, int i, Point p1);
	void checkAddressesSSE(bool compressed, Int key, int i, Point p1, Point p2, Point p3, Point p4);
	void output(std::string addr, std::string pAddr, std::string pAddrHex, std::string pubKey);

#ifdef WIN64
	HANDLE mutex;
	HANDLE ghMutex;	
#else
	pthread_mutex_t  mutex;
	pthread_mutex_t  ghMutex;	
#endif	

	bool isAlive(TH_PARAM* p);
	bool isSingularAddress(std::string pref);
	bool hasStarted(TH_PARAM* p);
	uint64_t getGPUCount();
	bool initAddress(std::string& address, ADDRESS_ITEM* it);
	void updateFound();
	void getGPUStartingKeys(Int& tRangeStart, Int& tRangeEnd, int groupSize, int numThreadsGPU, Point* publicKeys, uint64_t Progress);
	void enumCaseUnsentiveAddress(std::string s, std::vector<std::string>& list);
	void PrintStats(uint64_t keys_n, uint64_t keys_n_prev, double ttot, double tprev, Int taskSize, Int keycount);
	void saveBackup(int idxcount, double t_Paused, int gpuid);

	Secp256K1* secp;
	Int startKey;		
	uint64_t      counters[256];	
	double startTime;
	int searchType;
	int searchMode;
	bool stopWhenFound;
	bool endOfSearch;
	int numGPUs;
	int nbFoundKey;
	uint32_t nbAddress;
	std::string outputFile;
	bool useSSE;
	bool onlyFull;
	uint32_t maxFound;	
	std::vector<ADDRESS_TABLE_ITEM> addresses;
	std::vector<address_t> usedAddress;
	std::vector<LADDRESS> usedAddressL;
	std::vector<std::string>& inputAddresses;	

	BITCRACK_PARAM* bc;
	void saveProgress(TH_PARAM* p, Int& lastSaveKey, BITCRACK_PARAM* bc);

	Int firstGPUThreadLastPrivateKey;

	Int beta;
	Int lambda;
	Int beta2;
	Int lambda2;
};

#endif // VANITYH
