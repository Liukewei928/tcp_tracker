#include "misc/utc_offset.hpp"
#include <ctime>

UTCOffset* UTCOffset::get_instance() {
    if (!instance_) instance_ = new UTCOffset();
    return instance_;
}

int UTCOffset::get_offset() const { 
    return offset_; 
}

UTCOffset::UTCOffset() {
    time_t now = time(nullptr);
    struct tm* gmTime = gmtime(&now);
    struct tm* localTime = localtime(&now);
    offset_ = difftime(mktime(localTime), mktime(gmTime)) / 3600;
};
