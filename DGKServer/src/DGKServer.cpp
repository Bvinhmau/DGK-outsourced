#include "DGKServer.h"
#include "comm.h"
#include <DGKOutSourcedOperationsID.h>
#include <DGKOperations.h>
#include <DGKPublicKey.h>
#include <DGKPrivateKey.h>


#include<sys/time.h>
#include <iostream>
using namespace std;
#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#define WSSTART() {\
WORD wVersionRequested;\
WSADATA wsaData;\
int wsaerr;\
wVersionRequested = MAKEWORD(2, 2);\
wsaerr = WSAStartup(wVersionRequested, &wsaData);\
}
#else
#define WSSTART()
#endif

//#define DEBUG

DGKServer::DGKServer(){
};

double get_wall_time(){
	struct timeval time;
	if (gettimeofday(&time, NULL)){
		return 0;
	}
	return (double)time.tv_sec + (double)time.tv_usec * .000001;
}

char *addr;
char *infile;
int aflg;
int port;
int max_con;
int core;
int pbwt_n; // positions
int pbwt_m; //samples
int epsilon;
std::string tmp_dir_path;
std::string key_dir_path;

int setParam(int argc, char **argv)
{
	int opt;
	aflg=0;
	max_con = 1;
	int nopt = 0;
	core = 1;
	epsilon = 0;// longest match greater than epsilon
	tmp_dir_path="";
	key_dir_path="";
    while((opt = getopt(argc, argv, "p:a:n:d:")) != -1){
        switch(opt){
        case 'a':
			aflg=1;
			addr = optarg;
            break;
        case 'd':
			tmp_dir_path = optarg;
            break;
		case 'n':
			max_con = atoi(optarg);
			break;
        case 'p':
			port = atoi(optarg);
            break;


        default:
			fprintf(stderr, "Usage: %s [-a address] [-d tmpfile_dir_path] [-n max_connections] [-p port] ", argv[0]);
            exit(EXIT_FAILURE);
        }
    }
	if(1){ //tocheck
		return(0);
	}else{
		fprintf(stderr, "Usage: %s [-a address] [-d tmpfile_dir_path] [-n max_connections] [-p port] \n", argv[0]);
		exit(1);
	}
}


 #include <winsock2.h>
int main(int argc,char **argv)
{
 WSSTART();

    cout << "Starting DGKServer..." << endl;


    double wts, wte, all_s, all_e, calc_total=0, calc_head;;
	wts = get_wall_time();

	//ROT::SysInit();

	setParam(argc, argv);
	wte = get_wall_time();
	calc_head = wte - wts;;

	int sock0 = prepSSock();
    while(1){
		DGKServer s;
        int sock = acceptSSock(sock0);

		//std::ifstream ifs;
		//std::ofstream ofs;
       std::string  pubKeyfile  = "pubkey";
       std::string  privkeyfile  = "privkey";
		recvFile(sock, (char *)pubKeyfile.c_str());

    cout << "PubKey received" << endl;
        recvFile(sock, (char *)privkeyfile.c_str());

    cout << "PrivKey received" << endl;




    DGKPublicKey pubKey = DGKPublicKey();
    DGKPrivateKey privKey = DGKPrivateKey();


    load(pubKey, "pubKey");
    load(privKey, "privKey");

    std::string  tempciph  = "temp";
    recvFile(sock, (char *)tempciph.c_str());

    //std::string cipherString;
    ZZ cipher;
    std::ifstream myfile2;

    myfile2.open("temp");
    myfile2 >> cipher;
   // cipherString =  sstr.str();
    myfile2.close();

   // cipher =  DGKOperations::stringToZZ( cipherString);
    cout<<cipher<<endl;

    long plain = DGKOperations::decrypt(pubKey,privKey,cipher);

    cout<<plain<<endl;

    cout <<"poipoi"<<endl;
    int op = 0;
   // DGKOperations::sendInt(op,sock);
    long plain1 = 33;
    long plain2 = 4;
    ZZ cipher1  = DGKOperations::encrypt(pubKey, plain1);
    ZZ cipher2  = DGKOperations::encrypt(pubKey, plain2);

    std::tuple<ZZ, ZZ> tpl = DGKOperations::CipherMultiplication(pubKey,sock,cipher1,cipher2);
        ZZ result2 = DGKOperations::CipherMultiplicationHonnest(pubKey,sock,cipher1,cipher2);

    ZZ result = std::get<0>(tpl);

    long plainres = DGKOperations::decrypt(pubKey,privKey,result);
    long plainres2 = DGKOperations::decrypt(pubKey,privKey,result2);

    cout << "finres " << plainres << endl;
        cout << "finres " << plainres2 << endl;
        long u = pubKey.GetU();
for(int i = 0 ; i< 2; ++i){


          plain1 = NTL::RandomBnd(64);;
            plain2 =  NTL::RandomBnd(64);
       cipher1 =     DGKOperations::encrypt(pubKey, plain1);
  cipher2 =  DGKOperations::encrypt(pubKey, plain2);

    ZZ compari = DGKOperations::isSuperiorTo(pubKey,sock,cipher1,cipher2);
        cout <<  DGKOperations::decrypt(pubKey,privKey,cipher1)<< "vs " << DGKOperations::decrypt(pubKey,privKey,cipher2) << "->" << DGKOperations::decrypt(pubKey,privKey,compari) << endl;
}
   // DGKOperations::sendInt(sock,0);

       int numb = 10;
    int kk = 4;
std:vector< unsigned long> inputs(numb);

    std::vector<ZZ> inputscipher(numb);

    for (int j = 0 ; j < numb;  ++j)
    {
        unsigned long plain = NTL::RandomBnd(pow(2,pubKey.getL()-2));
        // cout <<"COMP "<< plain << " VS " << plain2 << "\n";
        ZZ cipher = DGKOperations::encrypt(pubKey,plain);
        inputs[j] = plain;
        inputscipher[j] = cipher;
    }


    vector<int> res;
    //res
    //res.push_back(ZZ(1));

    vector<int>  ids1;
    vector<ZZ>  ids2;
        std::chrono::milliseconds timeK (0);


    high_resolution_clock::time_point t1;
    high_resolution_clock::time_point t2;




  //ids1 = DGKOperations::topKMaxVanilla(pubKey,privKey,inputscipher,kk);




        t1 = high_resolution_clock::now();
    ids2 = DGKOperations::topKMaxSwap(pubKey,privKey,sock,inputscipher,kk);
  //ids1 = DGKOperations::topKMaxTournament(pubKey,privKey,sock,inputscipher,kk);

                t2 = high_resolution_clock::now();

    timeK =timeK + duration_cast<milliseconds>( t2 - t1 );


    cout <<"Top-k Swap " << " \n ";
    for (int i = 0 ; i < numb; ++i){
        cout << DGKOperations::decrypt(pubKey,privKey,inputscipher[i]) << " ";
    }
    cout << "\n";

    for (int i = 0 ; i < kk ; ++i){
         //       cout << DGKOperations::decrypt(pubKey,privKey,ids2[i]) << " ";

    }

    cout << "\n";
    cout<<timeK.count()<< "s"<<endl;
        DGKOperations::sendInt(sock,OPERATION_RESULT);

    }

    return 0;
}




