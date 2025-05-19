#ifndef DIRECTION_HPP
#define DIRECTION_HPP

enum class Direction {
    CLIENT_TO_SERVER, // Data flow C->S, buffer held by server logic
    SERVER_TO_CLIENT  // Data flow S->C, buffer held by client logic
};

#endif // DIRECTION_HPP
