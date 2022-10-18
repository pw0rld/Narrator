#include <stdio.h>
#include <string.h>
#include <string>
#include <iostream>
#include <sstream>
using namespace std;
int main()
{
    std::string test = "['1665471354957 @ 230']";
    test.erase(0, 2);
    test.erase(test.find("@"), test.find("]"));
    int64_t a = 1665471354959;
    std::stringstream ss;
    ss << test;
    int64_t i;
    ss >> i;
    int64_t b = a - i;
    cout << i << " " << b << endl;
    return 1;
}