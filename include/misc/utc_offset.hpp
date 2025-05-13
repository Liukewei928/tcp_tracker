#ifndef UTC_OFFSET_HPP
#define UTC_OFFSET_HPP

class UTCOffset {
public:
    static UTCOffset* get_instance();
    int get_offset() const;

private:
    static UTCOffset* instance_;
    int offset_;  // Offset in hours
    UTCOffset();
};

#endif // UTC_OFFSET_HPP
