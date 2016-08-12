#include <iostream>
#include <map>

#include <NTL/ZZ.h>
#include <stdint.h>
#include <DGKOperations.h>
#include <DGKPublicKey.h>
#include <DGKPrivateKey.h>
#include <tuple>
#define POSMOD(x,n) ((x % n + n) % n)

#include <chrono>
#include <stdlib.h>
#include <math.h>
#include <windows.h>
using namespace std;
using namespace std::chrono;
void test()
{
    unsigned long a = 10;
    unsigned long plain= 2;
    cout << "Welcome to DGK" << endl;
    ZZ test = NTL::RandomPrime_ZZ(a);
    cout << test << "\n";

    high_resolution_clock::time_point t1 = high_resolution_clock::now();
    std::tuple<DGKPrivateKey, DGKPublicKey> w = DGKOperations::GenerateKeys(8,160,1024);

    high_resolution_clock::time_point t2 = high_resolution_clock::now();

    auto duration = duration_cast<microseconds>( t2 - t1 ).count();


    cout << duration <<"mics \n";
    DGKPublicKey pubKey= std::get<1>(w);
    DGKPrivateKey privKey = std::get<0>(w);

    t1 = high_resolution_clock::now();
    ZZ cipher = DGKOperations::encrypt(pubKey,plain);

    t2 = high_resolution_clock::now();

    duration = duration_cast<microseconds>( t2 - t1 ).count();

    cout << duration <<"mics \n";
    cout << cipher << "\n";
    std::map<ZZ, unsigned long> lut;
    t1 = high_resolution_clock::now();

    lut = DGKOperations::generateLUT( pubKey,  privKey);

    t2 = high_resolution_clock::now();

    duration = duration_cast<microseconds>( t2 - t1 ).count();
    cout << duration <<"mics \n";

    t1 = high_resolution_clock::now();

    unsigned long plain2 = DGKOperations::decrypt( pubKey, privKey, cipher);

    t2 = high_resolution_clock::now();

    duration = duration_cast<microseconds>( t2 - t1 ).count();
    cout << duration <<"mics \n";
    cout << plain2 <<"result \n";

    t1 = high_resolution_clock::now();

    ZZ result = DGKOperations::DGKMultiply( pubKey, cipher, 5);

    t2 = high_resolution_clock::now();

    duration = duration_cast<nanoseconds>( t2 - t1 ).count();
    cout << duration <<"mics \n";
    unsigned long plain3 = DGKOperations::decrypt(  pubKey, privKey, result);

    cout << plain3 <<"result \n";
    t1 = high_resolution_clock::now();

    std::tuple<ZZ, ZZ>   betteroutput = DGKOperations::CipherMultiplication(pubKey,privKey,cipher,cipher);

    result = std::get<0>(betteroutput);
    ZZ asso = std::get<1>(betteroutput);

    duration = duration_cast<microseconds>( t2 - t1 ).count();
    cout << duration <<"mics \n";
    plain3 = DGKOperations::decrypt(  pubKey,privKey, result);

    cout << plain3 <<"result \n";

}
void testEncDec()
{



    for (int j = 0 ; j <1; ++j)
    {
//Sleep(500);
        std::tuple<DGKPrivateKey, DGKPublicKey> w = DGKOperations::GenerateKeys(16,160,1024);
        DGKPublicKey pubKey= std::get<1>(w);
        DGKPrivateKey privKey = std::get<0>(w);
        std::map<ZZ, unsigned long> lut;
        lut = DGKOperations::generateLUT( pubKey,  privKey);
        std::map<unsigned long, ZZ> glut = DGKOperations::generatePreCompLut( pubKey );

        std::map<unsigned long, ZZ> lutH = DGKOperations::generatePreCompLutSG( pubKey);
        //cout <<"u "<<pubKey.GetU()<<" sizeLUT "<< privKey.GetLUT().size() <<"\n";

        for (int i = 0 ; i <1; ++i)
        {
            unsigned long u = pubKey.GetU();
            // Generate all the blinding/challenge values
            unsigned long plain = NTL::RandomBnd(u);

            high_resolution_clock::time_point t1 = high_resolution_clock::now();
            ZZ cipher = DGKOperations::encrypt(pubKey,plain);
            high_resolution_clock::time_point t2 = high_resolution_clock::now();
            auto duration = duration_cast<microseconds>( t2 - t1 ).count();
            t1 = high_resolution_clock::now();
            ZZ cipher2 = DGKOperations::encrypt(pubKey,plain);
            t2 = high_resolution_clock::now();
            auto duration2 = duration_cast<microseconds>( t2 - t1 ).count();
            cout << "ENC " << duration2 << "uS\n";

            //cout << "ENC " << duration <<"uS vs"<< duration2 << "uS\n";
            t1 = high_resolution_clock::now();
            unsigned long result = DGKOperations::decrypt( pubKey, privKey, cipher);
            t2 = high_resolution_clock::now();
            auto duration3 = duration_cast<microseconds>( t2 - t1 ).count();
            cout << "DEC " << duration3 << "uS\n";

            if (plain != result)
            {
                cout << plain <<"ERROR\n";
                cout <<  "The privkey is \n VP : "  <<  privKey.GetVP()
                     << "\n VQ : " << privKey.GetVQ()<<
                     "\n P : " << privKey.GetP() <<
                     " \n Q : s" << privKey.GetQ() <<
                     " \n"  <<"\n";
                cout <<  "The pubkey is \n VP : "  <<  pubKey.GetG()
                     << "\n H : " <<pubKey.GetH() <<
                     " \n U : " << pubKey.GetU()   <<"\n";
                ZZ GVP = NTL::PowerMod(POSMOD(pubKey.GetG(),privKey.GetP()),privKey.GetVP(),privKey.GetP());
                ZZ GVQ = NTL::PowerMod(POSMOD(pubKey.GetG(),privKey.GetQ()),privKey.GetVQ(),privKey.GetQ());

                cout <<  "GVP : "  <<  GVP << "\n GVQ : " << GVQ <<"\n";


                /*
                   for (int w = 1 ; w <pubKey.GetU()* privKey.GetVQ() ;++w){
                        ZZ test = NTL::PowerMod(POSMOD(pubKey.GetG(),privKey.GetN() ),privKey.GetVP()  * w,privKey.GetN());
                   if (test == ZZ(1)) {
                           cout <<  "\n  ++++++++++++++++++"  << "\n";
                           cout <<  "\n  ++++++++++++++++++"  << "\n";

                           cout <<  "\n  VIOLE COND "  <<  privKey.GetVP()  * w << "\n";

                           cout <<  "\n  ++++++++++++++++++"  << "\n";
                           cout <<  "\n  ++++++++++++++++++"  << "\n";

                   }

                   }
                */
            }
        }
    }

}

void testHomorOp()
{
    for (int j = 0 ; j <1; ++j)
    {

        std::tuple<DGKPrivateKey, DGKPublicKey> w = DGKOperations::GenerateKeys(16,160,1024);
        DGKPublicKey pubKey= std::get<1>(w);
        DGKPrivateKey privKey = std::get<0>(w);
        std::map<ZZ, unsigned long> lut;
        lut = DGKOperations::generateLUT( pubKey,  privKey);
        unsigned long u = pubKey.GetU();
        for (int i = 0 ; i <1000; ++i)
        {
            // Generate all the blinding/challenge values
            unsigned long plain = NTL::RandomBnd(u);
            unsigned long plain2 = NTL::RandomBnd(u);

            ZZ cipher1 = DGKOperations::encrypt(pubKey,plain);
            ZZ cipher2 = DGKOperations::encrypt(pubKey,plain2);

            ZZ sum = DGKOperations::DGKAdd(pubKey,cipher1,cipher2);

            ZZ product = DGKOperations::DGKMultiply(pubKey,cipher1,plain2);

            //  product = DGKOperations::DGKMultiply(pubKey,product,u-1);

            unsigned long result = DGKOperations::decrypt( pubKey, privKey, sum);
            unsigned long result2 = DGKOperations::decrypt( pubKey, privKey, product);

            if (result != (plain + plain2)%u)
            {
                cout << "The summ of " << plain << " " << plain2 <<"caused error! \n";

            }
            if (  result2 != (((ZZ(plain)*ZZ(plain2))% u + u) % u) )
            {
                cout << "The product of " << plain << " " << plain2 <<"caused error! \n";
                cout <<  result2  <<  " vs" << (((ZZ(plain)*ZZ(plain2)) % u + u) % u)<<"caused error! \n";

            }
        }
    }

}

void testBetterTime()
{


    for (int j = 0 ; j <1; ++j)
    {

        high_resolution_clock::time_point t3 = high_resolution_clock::now();
        std::tuple<DGKPrivateKey, DGKPublicKey> w = DGKOperations::GenerateKeys(8,160,1024);
        high_resolution_clock::time_point t4 = high_resolution_clock::now();

        auto duration = duration_cast<seconds>( t4 - t3 ).count();
        cout <<"KeyGen"<< duration << " s\n";

        DGKPublicKey pubKey= std::get<1>(w);
        DGKPrivateKey privKey = std::get<0>(w);
        std::map<ZZ, unsigned long> lut;
        lut = DGKOperations::generateLUT( pubKey,  privKey);


        for (int i = 0 ; i <1000; ++i)
        {
            unsigned long u = pubKey.GetU();
            // Generate all the blinding/challenge values
            unsigned long plain = NTL::RandomBnd(u);
            unsigned long plain2 = NTL::RandomBnd(u);

            ZZ cipher1 = DGKOperations::encrypt(pubKey,plain);
            ZZ cipher2 = DGKOperations::encrypt(pubKey,plain2);

            high_resolution_clock::time_point t1 = high_resolution_clock::now();

            std::tuple<ZZ, ZZ>   betteroutput= DGKOperations::CipherMultiplication(pubKey,privKey,cipher1,cipher2);
            high_resolution_clock::time_point t2 = high_resolution_clock::now();
            auto duration = duration_cast<microseconds>( t2 - t1 ).count();
            cout <<"BetterTime"<< duration << "uS\n";

            ZZ     result = std::get<0>(betteroutput);
            ZZ asso = std::get<1>(betteroutput);

            unsigned long result2 = DGKOperations::decrypt(  pubKey, privKey, result);

            if (result2 != POSMOD(ZZ(plain) * ZZ(plain2), u))
            {
                cout << "The product of " << plain << " " << plain2 <<"caused error! \n";
                cout <<  result2  <<  " vs" << POSMOD(plain * plain2, u) <<"caused error! \n";
                unsigned long check = DGKOperations::decrypt(  pubKey, privKey, asso);
                cout <<" Response " << check <<" caused error! \n";

//cout <<  "The privkey is"  <<  privKey.GetVP() << " " << privKey.GetVQ()<< " " << privKey.GetP() << " " << privKey.GetQ() <<" "  <<"\n";
//           cout <<  "The pubkey is"  <<  pubKey.GetG() << " " <<pubKey.GetH() << " " << pubKey.GetU()   <<"\n";


            }
        }
    }
}

void benchmark()
{
    cout <<"Benchmark in Progress..." << " \n";
    bool isBTsplitted = 0;
    int numkeygen = 1;
    int numEncDe = 1;
    int numAdd = 1;
    int numBetterTimes = 1;
    int numComp = 1;

    high_resolution_clock::time_point t1;
    high_resolution_clock::time_point t2;

    std::chrono::microseconds timeEnc (0);
    std::chrono::microseconds timeDec (0);
    std::chrono::microseconds timeAdd(0) ;
    std::chrono::microseconds timeMul(0);

    std::chrono::microseconds timeBT (0);
    std::chrono::microseconds timeBTHonnest (0);

    std::chrono::seconds timeKeygen (0);
    std::chrono::microseconds timeComp (0);

    t1 = high_resolution_clock::now();
    std::tuple<DGKPrivateKey, DGKPublicKey> w = DGKOperations::GenerateKeys(8,160,1024);
    t2 = high_resolution_clock::now();

    timeKeygen =timeKeygen + duration_cast<seconds>( t2 - t1 );


    DGKPublicKey pubKey = DGKPublicKey();
    DGKPrivateKey privKey = DGKPrivateKey();

    DGKPublicKey pubKey2 =  std::get<1>(w);
    DGKPrivateKey privKey2 =std::get<0>(w);




    save(pubKey2,"exshort.txt");
    load(pubKey, "exshort.txt");
    save(pubKey,"ex2.txt");

    save(privKey2, "exPriv.txt");
    load(privKey, "exPriv.txt");
    save(privKey, "exPriv2.txt");
    cout <<"KeyGen "<< timeKeygen.count() << " s\n";
    unsigned long u = pubKey.GetU();
    for (int j = 0 ; j < numEncDe ; ++j)
    {

        unsigned long plain = NTL::RandomBnd(u);

        t1 = high_resolution_clock::now();
        ZZ cipher = DGKOperations::encrypt(pubKey,plain);
        t2 = high_resolution_clock::now();
        timeEnc = timeEnc + duration_cast<microseconds>( t2 - t1 );


        t1 = high_resolution_clock::now();
        unsigned long result = DGKOperations::decrypt( pubKey, privKey, cipher);
        t2 = high_resolution_clock::now();
        timeDec = timeDec + duration_cast<microseconds>( t2 - t1 );
        if (plain != result)
        {
            cout <<"ERROR" << "\n";

        }

    }

    cout <<"Encryption "<< timeEnc.count()/numEncDe << " us\n";
    cout <<"Decryption "<< timeDec.count()/numEncDe << " us\n";
    for (int j = 0 ; j < numComp;  ++j)
    {
        unsigned long plain = NTL::RandomBnd(pow(2,pubKey.getL()-2));
        unsigned long plain2 = NTL::RandomBnd(pow(2,pubKey.getL()-2));
        // cout <<"COMP "<< plain << " VS " << plain2 << "\n";
        // plain = plain2+1;
        ZZ cipher = DGKOperations::encrypt(pubKey,plain);
        ZZ cipher2 = DGKOperations::encrypt(pubKey,plain2);
        t1 = high_resolution_clock::now();

        ZZ result = DGKOperations::isSuperiorTo( pubKey, privKey, cipher, cipher2 );
        t2 = high_resolution_clock::now();
        timeComp = timeComp + duration_cast<microseconds>( t2 - t1 );
        long clearresult = DGKOperations::decrypt(pubKey,privKey,result);


        if(!(clearresult == 1 && plain >= plain2) && !(clearresult == 0 && plain < plain2) )
        {

            cout << "ERROR " <<"\n";
            cout << plain<< " vs  " << plain2 << "-> "<< clearresult << "\n";

            //cout << "ERROR " << plain<< " vs  " << plain2 << "-> "<< clearresult << "\n";
        }
        //cout <<"COMP "<< decresult << "\n";

        //cout <<"COMP "<< duration << "uS\n";
        //cout <<"COMP done\n";

    }
    cout <<"Comparison "<< timeComp.count()/numComp << " us\n";

    for (int j = 0 ; j < numAdd ; ++j)
    {
        long plain = NTL::RandomBnd(u);
        long plain2 = NTL::RandomBnd(u);

        ZZ cipher = DGKOperations::encrypt(pubKey,plain);
        ZZ cipher2 = DGKOperations::encrypt(pubKey,plain2);

        t1 = high_resolution_clock::now();
        ZZ result = DGKOperations::DGKAdd( pubKey, cipher2, cipher);
        t2 = high_resolution_clock::now();
        timeAdd = timeAdd + duration_cast<microseconds>( t2 - t1 );

        t1 = high_resolution_clock::now();
        ZZ result2 = DGKOperations::DGKMultiply( pubKey, cipher2, plain2);
        t2 = high_resolution_clock::now();
        timeMul = timeMul + duration_cast<microseconds>( t2 - t1 );
    }
    cout <<"Addition "<< timeAdd.count()/numAdd << " us\n";
    cout <<"Multiplication "<< timeMul.count()/numAdd << " us\n";
    for (int j = 0 ; j < numBetterTimes ; ++j)
    {

        unsigned long plain = NTL::RandomBnd(u);
        unsigned long plain2 = NTL::RandomBnd(u);

        ZZ cipher = DGKOperations::encrypt(pubKey,plain);
        ZZ cipher2 = DGKOperations::encrypt(pubKey,plain2);


        t1 = high_resolution_clock::now();
        std::tuple<ZZ, ZZ> result;
        if(isBTsplitted)
        {
            unsigned long secrets[5];
            std::tuple<ZZ, ZZ, ZZ>  requestcomp =DGKOperations::RequestOutSourcedMultiplication(secrets, pubKey, cipher, cipher2);
            std::tuple<ZZ, ZZ> servResponse = DGKOperations::PerfomOutSourcedMultiplication(pubKey,privKey, std::get<1>(requestcomp), std::get<2>(requestcomp), std::get<0>(requestcomp));
            result = DGKOperations::CompleteOutSourcedMultiplication(pubKey,  cipher, cipher2, std::get<0>(servResponse), std::get<1>(servResponse), secrets, std::get<1>(requestcomp), std::get<2>(requestcomp));
        }
        else
        {
            result = DGKOperations::CipherMultiplication(pubKey,privKey,cipher,cipher2);
        }
        t2 = high_resolution_clock::now();
        timeBT = timeBT + duration_cast<microseconds>( t2 - t1 );
        unsigned long result2 = DGKOperations::decrypt(  pubKey, privKey,  std::get<0>(result));

        if (result2 != POSMOD(ZZ(plain) * ZZ(plain2), u))
        {
            cout << "The product of " << plain << " " << plain2 <<"caused error! \n";
            cout <<  result2  <<  " vs" << POSMOD(plain * plain2, u) <<"caused error! \n";
            unsigned long check = DGKOperations::decrypt(  pubKey, privKey,  std::get<1>(result));
            cout <<" Response " << check <<" caused error! \n";
        }
    }
    cout <<"BetterTimes "<< timeBT.count()/numBetterTimes << " us\n";

    for (int j = 0 ; j < numBetterTimes ; ++j)
    {

        unsigned long plain = NTL::RandomBnd(u);
        unsigned long plain2 = NTL::RandomBnd(u);

        ZZ cipher = DGKOperations::encrypt(pubKey,plain);
        ZZ cipher2 = DGKOperations::encrypt(pubKey,plain2);


        t1 = high_resolution_clock::now();
        ZZ result;

        result = DGKOperations::CipherMultiplicationHonnest(pubKey,privKey,cipher,cipher2);

        t2 = high_resolution_clock::now();
        timeBTHonnest = timeBTHonnest + duration_cast<microseconds>( t2 - t1 );
        unsigned long result2 = DGKOperations::decrypt(  pubKey, privKey,  result);

        if (result2 != POSMOD(ZZ(plain) * ZZ(plain2), u))
        {
            cout << "The product of " << plain << " " << plain2 <<"caused error! \n";
            cout <<  result2  <<  " vs" << POSMOD(plain * plain2, u) <<"caused error! \n";
        }
    }
    cout <<"BetterTimesHonnest "<< timeBTHonnest.count()/numBetterTimes << " us\n";


    // DGKPublicKey pubKey = DGKPublicKey();
    // DGKPrivateKey privKey = DGKPrivateKey();
    int numb = 100;
    int kk = 10;
std:
    vector< unsigned long > inputs(numb);

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
    vector<int>  ids2;
    std::chrono::microseconds timecompVanilla (0);

    t1 = high_resolution_clock::now();

    ids1 = DGKOperations::topKMaxVanilla(pubKey,privKey,inputscipher,kk);

    t2 = high_resolution_clock::now();
    timecompVanilla = duration_cast<milliseconds>( t2 - t1 );
    cout <<"Top-k vanilla " << timecompVanilla.count() << " \n ";

    std::chrono::microseconds timecomptournament (0);

    t1 = high_resolution_clock::now();

    ids2 = DGKOperations::topKMaxTournament(pubKey,privKey,inputscipher,kk);

    t2 = high_resolution_clock::now();
    timecomptournament = duration_cast<milliseconds>( t2 - t1 );

    cout <<"Top-k Tournament "<< timecomptournament.count() << " \n ";


    /**
        for (int i = 0 ; i < res.size() ; ++i){
            int el = res[i];
            cout <<" "<< el<< " \n ";

        }
    **/
}

void conversion()
{
    cout << "ZTOS!" <<"\n";

    high_resolution_clock::time_point   t1 = high_resolution_clock::now();
    ZZ start = NTL::RandomPrime_ZZ(1024,10);
    high_resolution_clock::time_point   t2 = high_resolution_clock::now();

    auto    timeKeygen = duration_cast<milliseconds>( t2 - t1 ).count();
    cout << timeKeygen <<  " RandGen!" <<"\n";

    t1 = high_resolution_clock::now();
    string toast = DGKOperations::ZZToString(start);
    t2 = high_resolution_clock::now();

    timeKeygen = duration_cast<milliseconds>( t2 - t1 ).count();
    cout << timeKeygen <<  " ZZToStr!" <<"\n";




    cout << "done!" <<"\n";

    cout << start <<" \n";

    cout << toast <<" \n";
    std::ofstream myfile;
    string toast2 ;
    myfile.open ("toast.txt",  ofstream::binary);
    myfile << toast;

    myfile.close();
    std::ifstream myfile2;

    stringstream sstr;



    myfile2.open("toast.txt",  ifstream::binary);
    sstr << myfile2.rdbuf();
    toast2 =  sstr.str();
    myfile2.close();
    cout << toast2 <<" \n";

    t1 = high_resolution_clock::now();
    ZZ result = DGKOperations::stringToZZ(toast2);
    t2 = high_resolution_clock::now();
    timeKeygen = duration_cast<milliseconds>( t2 - t1 ).count();

//    ZZ s = ZZFromHexString("a34");





    // ZZ start = ZZ(38352324);

    cout << timeKeygen <<  " StrToZZ!" <<"\n";

    cout << result <<" \n";

}
void ClientServer(){
    }

int main()
{
    // cout << "Starting Enc/Dec test" <<"\n";
    // testEncDec();
    //  cout << "done!" <<"\n";
    //  cout << "Starting HomoOp test" <<"\n";
    // testHomorOp();
    // cout << "done!" <<"\n";
    //cout << "Starting BetterTime test" <<"\n";
    //testBetterTime();
    benchmark();




    cout << "done!" <<"\n";


    return 0;
}
