#ifndef DGKWRONGPARAMETER_H
#define DGKWRONGPARAMETER_H

#include <string>
#include <stdlib.h>

using namespace std;

class WrongParameterException : public std::runtime_error
{
public:
    WrongParameterException(const std::string& message)
        : std::runtime_error(message) { };
} ;
#endif // DGKWRONGPARAMETER_H
