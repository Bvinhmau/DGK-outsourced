#include "DGKServer.h"
#include "comm.h"

#include<sys/time.h>

//#define DEBUG




double DGKServer::get_wall_time(){
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
	tmp_dir_path="";
	key_dir_path="";
    while((opt = getopt(argc, argv, "p:a:n:c:r:f:m:d:k:e:")) != -1){
        switch(opt){
        case 'a':
			aflg=1;
			addr = optarg;
            break;
        case 'd':
			tmp_dir_path = optarg;
            break;
        case 'e':
			epsilon = atoi(optarg);
            break;
        case 'k':
			key_dir_path = optarg;
            break;
		case 'n':
			max_con = atoi(optarg);
			break;
        case 'p':
			port = atoi(optarg);
            break;
        case 'c':
			nopt++;
			pbwt_n = atoi(optarg);
            break;
        case 'r':
			nopt++;
			pbwt_m = atoi(optarg);
            break;
        case 'f':
			nopt++;
			infile = optarg;
            break;
		case 'm':
			core = atoi(optarg);
			break;
        default:
			fprintf(stderr, "Usage: %s [-a address] [-d tmpfile_dir_path] [-e epsilon ][-m threads] [-n max_connections] [-p port] -f pbwt_file -r row -c column\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }
	if(nopt==3){
		return(0);
	}else{
		fprintf(stderr, "Usage: %s [-a address] [-d tmpfile_dir_path] [-e epsilon ][-m threads] [-n max_connections] [-p port] -f pbwt_file -r row -c column\n", argv[0]);
		exit(1);
	}
}

int main4(int argc,char **argv)
{
}
