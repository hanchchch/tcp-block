#include "kmp.h"

std::vector<int> getPi(char* p, int p_size){
    int j = 0;
    std::vector<int> pi(p_size, 0);
    for(int i = 1; i < p_size; i++) {
        while(j > 0 && p[i] != p[j])
            j = pi[j-1];
        if(p[i] == p[j])
            pi[i] = ++j;
    }
    return pi;
}

bool kmp(char* haystack, int size_haystack, char* niddle, int size_niddle) {
    auto pi = getPi(niddle, size_niddle);
    int j = 0;
    for(int i = 0 ; i < size_haystack ; i++) {
        while(j>0 && haystack[i] != niddle[j])
            j = pi[j-1];
        if(haystack[i] == niddle[j]) {
            if(j == size_niddle-1) {
                return true;
            } else {
                j++;
            }
        }
    }
    return false;
}
// https://gist.github.com/bowbowbow/a7e19689481d42b28a42#file-kmp-cpp