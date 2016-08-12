#include "comm.h"

#include<sys/time.h>

//#define DEBUG

#ifdef DEBUG
#define DBG_PRT(...)  printf(__VA_ARGS__)
#else
#define DBG_PRT(...)
#endif

double get_wall_time(){
	struct timeval time;
	if (gettimeofday(&time, NULL)){
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
    while((opt = getopt(argc, argv, "h:p:q:m:d:k:")) != -1){
        switch(opt){
        case 'h':
			nopt++;
			host = optarg;
            break;
        case 'p':
			port = atoi(optarg);
            break;
        case 'q':
			nopt++;
			qfile = optarg;
            break;
		case 'm':
			core = atoi(optarg);
			break;
        case 'd':
			tmp_dir_path = optarg;
            break;
        case 'k':
			key_dir_path = optarg;
            break;
        default:
			fprintf(stderr, "Usage: %s [-d tmpfile_dir_path] [-k key_dir_path] [-m threads] [-p port] -h host -q queryfile\n", argv[0]);
			//            fprintf(stderr, "setup: %s query\n true_column\n dummy_column1\n dummy_column2\n ...\n -1\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }
	if(nopt==2){
		return(0);
	}else{
		fprintf(stderr, "Usage: %s [-d tmpfile_dir_path] [-k key_dir_path] [-m threads] [-p port] -h host -q queryfile\n", argv[0]);
		exit(1);
	}
}
int main2(int argc, char** argv)
{
}
