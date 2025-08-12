#ifndef WIREFORMAT_HPP
#define WIREFORMAT_HPP

#include <arpa/inet.h>
#include <boost/cstdint.hpp>
#include <iostream>
#include <stdexcept>
#include <vector>
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#include "utils.hpp"
#include <endian.h>
#include <sys/socket.h>
#include <sys/types.h>

class WireFormat
{
private:
    uint16_t               mBufferSize;
    uint16_t               mEnd;
    std::vector<uint8_t *> mBuffers;

    void checkIndex( uint16_t i ) const
    {
        if ( i >= mEnd )
            throw std::runtime_error( "range error" );
    }

public:
    WireFormat( uint16_t buffer_size = 512 );
    WireFormat( const PacketData &data, uint16_t buffer_size = 512 );
    WireFormat( const uint8_t *begin, const uint8_t *end, uint16_t buffer_size = 512 );
    WireFormat( const WireFormat & );
    WireFormat &operator=( const WireFormat &rhs );

    ~WireFormat();

    void push_back( uint8_t v )
    {
        if ( mEnd % mBufferSize == 0 )
            mBuffers.push_back( new uint8_t[ mBufferSize ] );

        *( mBuffers.back() + mEnd % mBufferSize ) = v;
        mEnd++;
    }

    uint8_t pop_back()
    {
        if ( mEnd == 0 )
            throw std::runtime_error( "cannot pop_back because buffer is emptry." );
        uint8_t ret = ( *this )[ mEnd - 1 ];
        mEnd--;
        return ret;
    }

    void clear();

    void pushUInt8( uint8_t v )
    {
        push_back( v );
    }

    void pushUInt16( uint16_t v )
    {
        push_back( (uint8_t)( 0xff & ( v >> 0 ) ) );
        push_back( (uint8_t)( 0xff & ( v >> 8 ) ) );
    }

    void pushUInt32( uint32_t v )
    {
        push_back( (uint8_t)( 0xff & ( v >> 0 ) ) );
        push_back( (uint8_t)( 0xff & ( v >> 8 ) ) );
        push_back( (uint8_t)( 0xff & ( v >> 16 ) ) );
        push_back( (uint8_t)( 0xff & ( v >> 24 ) ) );
    }

    void pushUInt64( uint64_t v )
    {
        push_back( (uint8_t)( 0xff & ( v >> 0 ) ) );
        push_back( (uint8_t)( 0xff & ( v >> 8 ) ) );
        push_back( (uint8_t)( 0xff & ( v >> 16 ) ) );
        push_back( (uint8_t)( 0xff & ( v >> 24 ) ) );
        push_back( (uint8_t)( 0xff & ( v >> 32 ) ) );
        push_back( (uint8_t)( 0xff & ( v >> 40 ) ) );
        push_back( (uint8_t)( 0xff & ( v >> 48 ) ) );
        push_back( (uint8_t)( 0xff & ( v >> 56 ) ) );
    }

    void pushUInt16HtoN( uint16_t v )
    {
        pushUInt16( htons( v ) );
    }
    void pushUInt32HtoN( uint32_t v )
    {
        pushUInt32( htonl( v ) );
    }
    void pushUInt64HtoN( uint64_t v )
    {
        pushUInt64( htobe64( v ) );
    }

    void pushBuffer( const uint8_t *begin, const uint8_t *end )
    {
        for ( ; begin != end; begin++ )
            push_back( *begin );
    }

    void pushBuffer( const PacketData &data )
    {
        pushBuffer( &data[ 0 ], &data[ 0 ] + data.size() );
    }

    void pushBuffer( const std::string &str )
    {
        pushBuffer( reinterpret_cast<const uint8_t *>( str.c_str() ),
                    reinterpret_cast<const uint8_t *>( str.c_str() ) + str.size() );
    }

    const uint8_t &operator[]( uint16_t i ) const
    {
        checkIndex( i );

        return mBuffers[ i / mBufferSize ][ i % mBufferSize ];
    }

    uint8_t &operator[]( uint16_t i )
    {
        checkIndex( i );

        return mBuffers[ i / mBufferSize ][ i % mBufferSize ];
    }

    const uint8_t &at( uint16_t i ) const
    {
        return ( *this )[ i ];
    }

    uint16_t size() const
    {
        return mEnd;
    }

    bool operator<( const WireFormat &rhs ) const;

    template <class UnaryFunction>
    void foreach ( UnaryFunction func ) const
    {
        for ( uint16_t i = 0; i < size(); i++ ) {
            func( at( i ) );
        }
    }

    template <class BinaryFunction>
    void foreachBuffers( BinaryFunction func ) const
    {
        int last_buffer_index = mBuffers.size() - 1;
        for ( int i = 0; i < last_buffer_index; i++ ) {
            func( mBuffers[ i ], mBuffers[ i ] + mBufferSize );
        }
        func( mBuffers[ last_buffer_index ], mBuffers[ last_buffer_index ] + mEnd % mBufferSize );
    }

    uint16_t   send( int fd, const sockaddr *dest, socklen_t dest_length, int flags = 0 ) const;
    PacketData get() const;

    struct MessageHeader {
        msghdr header;

        MessageHeader();
        ~MessageHeader();

        void setBuffers( uint16_t size, const std::vector<uint8_t *>, uint16_t buffer_size );
        void setDestination( const sockaddr *dest, uint16_t len );
    };

    uint16_t getBufferSize() const
    {
        return mBufferSize;
    }
};

#endif
