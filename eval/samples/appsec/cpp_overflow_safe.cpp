#include <string>

std::string copy_tag(const char *input) {
    return std::string(input).substr(0, 16);
}
