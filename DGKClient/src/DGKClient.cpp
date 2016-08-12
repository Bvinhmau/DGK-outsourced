#include "DGKClient.h"
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

DGKClient::DGKClient()
{
};
double get_wall_time()
{
    struct timeval time;
    if (gettimeofday(&time, NULL))
    {
        return 0;
    }
    return (double)time.tv_sec + (double)time.tv_usec * .000001;
}

char *qfile;
char *host;
int port;
int core;
//std::string tmp_dir_path;
//std::string key_dir_path;

std::string tmp_dir_path;
std::string key_dir_path;

int setParam(int argc, char **argv)
{
    int opt;
    int nopt=0;
    int core=1;
    tmp_dir_path="";
    key_dir_path="";
    while((opt = getopt(argc, argv, "h:p:d:")) != -1)
    {
        switch(opt)
        {
        case 'h':
            nopt++;
            host = optarg;
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'd':
            tmp_dir_path = optarg;
            break;
        default:
            fprintf(stderr, "Usage: %s [-d tmpfile_dir_path] [-p port] -h host \n", argv[0]);
            //            fprintf(stderr, "setup: %s query\n true_column\n dummy_column1\n dummy_column2\n ...\n -1\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    if(1)  // TODO rederivate a condition for failing
    {
        return(0);
    }
    else
    {
        fprintf(stderr, "Usage: %s [-d tmpfile_dir_path]  [-p port] -h host\n", argv[0]);
        exit(1);
    }
}


void waitForOperation(DGKPublicKey pubkey, DGKPrivateKey privKey, int stocking)
{
    int waiting = 1;
    while (waiting)
    {


        std::string  nextop  = "nextop";
        int op;
        recvFile(stocking, (char *)nextop.c_str());
        std::ifstream myfile;
        myfile.open (nextop);
        myfile >> op;


        if (op == OPERATION_RESULT )
        {
            waiting =  0 ;
        }
        else if (op == DO_OUTSOURCEDMULTIPLICATION)
        {
        DGKOperations::PerformMultiplicationOutsourced(pubkey,privKey,stocking);
        }
        else if (op==  DO_OUTSOURCEDHONNESTMULTIPLICATION )
        {
            DGKOperations::PerformMultiplicationOutsourcedHonnest( pubkey,  privKey,        stocking);
        }
               else if (op==  DO_COMPARISONFIRSTPART )
        {
            DGKOperations::isSuperiorToFirstOutsourcedPart( pubkey,  privKey,        stocking);
        }
    }
}
int main(int argc, char** argv)
{

    WSSTART();
    int recvSize=0;
    int sentSize=0;
    double wts, wte, all_s, all_e, calc_total=0;
    all_s = get_wall_time();
    wts = get_wall_time();

    DGKClient c;


    setParam(argc, argv);
    wte = get_wall_time();
    calc_total += wte - wts;
    int sock = prepCSock(host);

    std::tuple<DGKPrivateKey, DGKPublicKey> w = DGKOperations::GenerateKeys(8,160,1024);


    DGKPublicKey pubKey= std::get<1>(w);
    DGKPrivateKey privKey = std::get<0>(w);

    save(pubKey, "pubKey.txt");
    save(privKey,"privKey.txt");

    std::string pub =  "pubKey.txt";
    std::string priv =  "privKey.txt";


    sendFile(sock, (char *)pub.c_str());
    cout << "PubKey sent" << endl;

    sendFile(sock, (char *)priv.c_str());

    cout << "PrivKey sent" << endl;

    long plain = 42;

    ZZ cipher = DGKOperations::encrypt(pubKey,plain);


    cout<<cipher<<endl;






    std::ofstream myfile;
    myfile.open ("temp.txt");
    myfile << cipher;

    myfile.close();
    cout << "written" << endl;
    std::string tmp = "temp.txt";
    sendFile(sock, (char *)tmp.c_str());
    cout << "sent" << endl;

    waitForOperation(pubKey,privKey,sock);
}


