#include "dns.hpp"
#include "utils.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <boost/lexical_cast.hpp>
#include <boost/log/trivial.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <netinet/in.h>
#include <openssl/hmac.h>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#include <endian.h>

namespace dns
{
    void generateQuestion( const QuestionSectionEntry &q, WireFormat &message, OffsetDB &offset );
    void
    generateResourceRecord( const ResourceRecord &r, WireFormat &message, OffsetDB &offset, bool compression = true );
    uint32_t getQuestionSize( const QuestionSectionEntry &q, uint32_t begin, OffsetDB &offset );
    uint32_t
    getResourceRecordSize( const ResourceRecord &r, uint32_t begin, OffsetDB &offset, bool compression = true );
    typedef std::pair<QuestionSectionEntry, const uint8_t *> QuestionSectionEntryPair;
    typedef std::pair<ResourceRecord, const uint8_t *>       ResourceRecordPair;
    QuestionSectionEntryPair parseQuestion( const uint8_t *begin, const uint8_t *end, const uint8_t *section );
    ResourceRecordPair       parseResourceRecord( const uint8_t *begin, const uint8_t *end, const uint8_t *section );
    OptPseudoRecord          parseOPTPseudoRecord( const ResourceRecord & );

    static const uint8_t *
    parseCharacterString( const uint8_t *begin, const uint8_t *packet_end, std::string &ref_output )
    {
        if ( begin == NULL || packet_end == NULL )
            throw std::logic_error( "begin, packet end must not be NULL" );
        if ( begin == packet_end )
            throw FormatError( "character-string length >= 1" );

        const uint8_t *pos  = begin;
        uint8_t        size = get_bytes<uint8_t>( &pos );

        if ( pos + size > packet_end )
            throw FormatError( "character-string size is too long than end of packet" );

        ref_output.assign( reinterpret_cast<const char *>( pos ), size );
        pos += size;
        return pos;
    }

    uint16_t QuestionSectionEntry::size() const
    {
        return mDomainname.size() + sizeof( mType ) + sizeof( mClass );
    }

    uint32_t ResourceRecord::size() const
    {
        return mDomainname.size() + sizeof( mType ) + sizeof( mClass ) + sizeof( mTTL ) +
               sizeof( uint16_t ) + // size of resource data size
               mRData->size();
    }


    void MessageInfo::generateMessage( WireFormat &message ) const
    {
        OffsetDB offset_db;

        PacketHeaderField header;
        header.id                   = htons( mID );
        header.opcode               = mOpcode;
        header.query_response       = mQueryResponse;
        header.authoritative_answer = mAuthoritativeAnswer;
        header.truncation           = mTruncation;
        header.recursion_desired    = mRecursionDesired;
        header.recursion_available  = mRecursionAvailable;
        header.zero_field           = 0;
        header.authentic_data       = mAuthenticData;
        header.checking_disabled    = mCheckingDisabled;
        header.response_code        = mResponseCode;

        std::vector<ResourceRecord> additional = mAdditionalSection;

        if ( isEDNS0() ) {
            additional.push_back( generateOptPseudoRecord( mOptPseudoRR ) );
        }

        header.question_count              = htons( mQuestionSection.size() );
        header.answer_count                = htons( mAnswerSection.size() );
        header.authority_count             = htons( mAuthoritySection.size() );
        header.additional_infomation_count = htons( additional.size() );

        message.pushBuffer( reinterpret_cast<const uint8_t *>( &header ),
                            reinterpret_cast<const uint8_t *>( &header ) + sizeof( header ) );

        for ( auto q : mQuestionSection ) {
            generateQuestion( q, message, offset_db );
        }
        for ( auto q : mAnswerSection ) {
            generateResourceRecord( q, message, offset_db );
        }
        for ( auto q : mAuthoritySection ) {
            generateResourceRecord( q, message, offset_db );
        }
        for ( auto q : additional ) {
            generateResourceRecord( q, message, offset_db );
        }
    }

    uint32_t MessageInfo::getMessageSize() const
    {
        uint32_t pos = 0;
        OffsetDB offset_db;

        pos += sizeof( PacketHeaderField );

        std::vector<ResourceRecord> additional = mAdditionalSection;

        if ( isEDNS0() ) {
            additional.push_back( generateOptPseudoRecord( mOptPseudoRR ) );
        }

        pos += ( 2 * 4 ); // QDCOUNT + ANCOUNT + NSCOUNT + ADCOUNT

        for ( auto q : mQuestionSection ) {
            uint32_t size = getQuestionSize( q, pos, offset_db );
            pos += size;
        }
        for ( auto a : mAnswerSection ) {
            uint32_t size = getResourceRecordSize( a, pos, offset_db );
            pos += size;
        }
        for ( auto a : mAuthoritySection ) {
            uint32_t size = getResourceRecordSize( a, pos, offset_db );
            pos += size;
        }
        for ( auto a : additional ) {
            uint32_t size = getResourceRecordSize( a, pos, offset_db );
            pos += size;
        }

        return pos;
    }

    void MessageInfo::addOption( std::shared_ptr<OptPseudoRROption> opt )
    {
        std::dynamic_pointer_cast<RecordOptionsData>( mOptPseudoRR.mOptions )->add( opt );
    }

    MessageInfo parseDNSMessage( const uint8_t *begin, const uint8_t *end )
    {
        BOOST_LOG_TRIVIAL( trace ) << "dns.message.parse: parse message ";

        const uint8_t *packet = begin;

        if ( ( end - begin ) < sizeof( PacketHeaderField ) ) {
            throw FormatError( "too short message size( less than DNS message header size )." );
        }

        MessageInfo              packet_info;
        const PacketHeaderField *header = reinterpret_cast<const PacketHeaderField *>( begin );

        packet_info.mID                  = ntohs( header->id );
        packet_info.mQueryResponse       = header->query_response;
        packet_info.mOpcode              = header->opcode;
        packet_info.mAuthoritativeAnswer = header->authoritative_answer;
        packet_info.mTruncation          = header->truncation;
        packet_info.mRecursionAvailable  = header->recursion_available;
        packet_info.mRecursionDesired    = header->recursion_desired;
        packet_info.mCheckingDisabled    = header->checking_disabled;
        packet_info.mAuthenticData       = header->authentic_data;
        packet_info.mResponseCode        = header->response_code;

        int question_count              = ntohs( header->question_count );
        int answer_count                = ntohs( header->answer_count );
        int authority_count             = ntohs( header->authority_count );
        int additional_infomation_count = ntohs( header->additional_infomation_count );

        BOOST_LOG_TRIVIAL( trace ) << "dns.domainname.parse: "
                                   << "qd: " << question_count << ", "
                                   << "ad: " << answer_count << ", "
                                   << "ns: " << authority_count << ", "
                                   << "ar: " << additional_infomation_count;

        packet += sizeof( PacketHeaderField );
        for ( int i = 0; i < question_count; i++ ) {
            QuestionSectionEntryPair pair = parseQuestion( begin, end, packet );
            packet_info.mQuestionSection.push_back( pair.first );
            packet = pair.second;
        }
        for ( int i = 0; i < answer_count; i++ ) {
            ResourceRecordPair pair = parseResourceRecord( begin, end, packet );
            packet_info.mAnswerSection.push_back( pair.first );
            packet = pair.second;
        }
        for ( int i = 0; i < authority_count; i++ ) {
            ResourceRecordPair pair = parseResourceRecord( begin, end, packet );
            packet_info.mAuthoritySection.push_back( pair.first );
            packet = pair.second;
        }
        for ( int i = 0; i < additional_infomation_count; i++ ) {
            ResourceRecordPair pair = parseResourceRecord( begin, end, packet );
            if ( pair.first.mType == TYPE_OPT ) {
                packet_info.mIsEDNS0                  = true;
                packet_info.mOptPseudoRR.mDomainname  = pair.first.mDomainname;
                packet_info.mOptPseudoRR.mPayloadSize = pair.first.mClass;
                packet_info.mOptPseudoRR.mRCode       = ( 0xff000000 & pair.first.mTTL ) >> 24;
                packet_info.mOptPseudoRR.mVersion     = ( 0x00ff0000 & pair.first.mTTL ) >> 16;
                packet_info.mOptPseudoRR.mDOBit       = ( 0x00008000 & pair.first.mTTL ) ? true : false;
                packet_info.mOptPseudoRR.mOptions     = pair.first.mRData;
            }
            if ( pair.first.mType == TYPE_TSIG && pair.first.mClass == CLASS_IN ) {
                packet_info.mIsTSIG = true;
                packet_info.mTSIGRR = dynamic_cast<const RecordTSIGData &>( *( pair.first.mRData ) );
            }
            packet_info.mAdditionalSection.push_back( pair.first );
            packet = pair.second;
        }

        return packet_info;
    }

    void generateQuestion( const QuestionSectionEntry &question, WireFormat &message, OffsetDB &offset_db )
    {
        offset_db.outputWireFormat( question.mDomainname, message );
        message.pushUInt16HtoN( question.mType );
        message.pushUInt16HtoN( question.mClass );
    }

    uint32_t getQuestionSize( const QuestionSectionEntry &question, uint32_t begin, OffsetDB &offset_db )
    {
        uint32_t domainname_size = offset_db.getOutputWireFormatSize( question.mDomainname, begin );
        return domainname_size + 2 + 2; // domainname + type + class
    }

    QuestionSectionEntryPair parseQuestion( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *p )
    {
        QuestionSectionEntry question;
        const uint8_t       *pos = Domainname::parsePacket( question.mDomainname, packet_begin, packet_end, p );

        question.mType  = ntohs( get_bytes<uint16_t>( &pos ) );
        question.mClass = ntohs( get_bytes<uint16_t>( &pos ) );

        return QuestionSectionEntryPair( question, pos );
    }

    void
    generateResourceRecord( const ResourceRecord &response, WireFormat &message, OffsetDB &offset_db, bool compression )
    {
        if ( compression )
            offset_db.outputWireFormat( response.mDomainname, message );
        else
            response.mDomainname.outputWireFormat( message );
        message.pushUInt16HtoN( response.mType );
        message.pushUInt16HtoN( response.mClass );
        message.pushUInt32HtoN( response.mTTL );
        if ( response.mRData ) {
            uint32_t rdata_size = 0;
            if ( compression )
                rdata_size = response.mRData->size( offset_db, message.size() );
            else
                rdata_size = response.mRData->size();
            message.pushUInt16HtoN( rdata_size );
            response.mRData->outputWireFormat( message, offset_db );
        } else {
            message.pushUInt16HtoN( 0 );
        }
    }

    uint32_t
    getResourceRecordSize( const ResourceRecord &response, uint32_t begin, OffsetDB &offset_db, bool compression )
    {
        uint32_t size = 0;
        uint32_t pos  = begin;

        if ( compression ) {
            size = offset_db.getOutputWireFormatSize( response.mDomainname, pos );
            pos += size;
        } else {
            size = response.mDomainname.size();
            pos += size;
        }

        size += ( 2 + 2 + 4 ); // Type + Class + TTL
        pos += ( 2 + 2 + 4 );  // Type + Class + TTL

        if ( response.mRData ) {
            size += 2; // rdata size
            pos += 2;  // rdata size

            uint32_t rdata_size = 0;
            if ( compression )
                rdata_size = response.mRData->size( offset_db, pos );
            else
                rdata_size = response.mRData->size();
            size += rdata_size;
            pos += rdata_size;
        } else {
            size += 2;
            pos += 2;
        }

        return size;
    }

    ResourceRecordPair
    parseResourceRecord( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *section_begin )
    {
        BOOST_LOG_TRIVIAL( trace ) << "dns.rr.parse: parse resource record";

        ResourceRecord sec;

        const uint8_t *pos   = Domainname::parsePacket( sec.mDomainname, packet_begin, packet_end, section_begin );
        sec.mType            = ntohs( get_bytes<uint16_t>( &pos ) );
        sec.mClass           = ntohs( get_bytes<uint16_t>( &pos ) );
        sec.mTTL             = ntohl( get_bytes<uint32_t>( &pos ) );
        uint16_t data_length = ntohs( get_bytes<uint16_t>( &pos ) );

        BOOST_LOG_TRIVIAL( trace ) << "dns.rr.parse: parse " << typeCodeToString( sec.mType ) << " resource record";
        RDATAPtr parsed_data;
        switch ( sec.mType ) {
        case TYPE_A:
            parsed_data = RecordA::parse( pos, pos + data_length );
            break;
        case TYPE_AAAA:
            parsed_data = RecordAAAA::parse( pos, pos + data_length );
            break;
        case TYPE_NS:
            parsed_data = RecordNS::parse( packet_begin, packet_end, pos, pos + data_length );
            break;
        case TYPE_CNAME:
            parsed_data = RecordCNAME::parse( packet_begin, packet_end, pos, pos + data_length );
            break;
        case TYPE_NAPTR:
            parsed_data = RecordNAPTR::parse( packet_begin, packet_end, pos, pos + data_length );
            break;
        case TYPE_DNAME:
            parsed_data = RecordDNAME::parse( packet_begin, packet_end, pos, pos + data_length );
            break;
        case TYPE_WKS:
            parsed_data = RecordWKS::parse( packet_begin, packet_end, pos, pos + data_length );
            break;
        case TYPE_MX:
            parsed_data = RecordMX::parse( packet_begin, packet_end, pos, pos + data_length );
            break;
        case TYPE_TXT:
            parsed_data = RecordTXT::parse( packet_begin, packet_end, pos, pos + data_length );
            break;
        case TYPE_SPF:
            parsed_data = RecordSPF::parse( packet_begin, packet_end, pos, pos + data_length );
            break;
        case TYPE_SOA:
            parsed_data = RecordSOA::parse( packet_begin, packet_end, pos, pos + data_length );
            break;
        case TYPE_CAA:
            parsed_data = RecordCAA::parse( packet_begin, packet_end, pos, pos + data_length );
            break;
        case TYPE_SRV:
            parsed_data = RecordSRV::parse( packet_begin, packet_end, pos, pos + data_length );
            break;
        case TYPE_DNSKEY:
            parsed_data = RecordDNSKEY::parse( packet_begin, packet_end, pos, pos + data_length );
            break;
        case TYPE_NSEC:
            parsed_data = RecordNSEC::parse( packet_begin, packet_end, pos, pos + data_length );
            break;
        case TYPE_NSEC3:
            parsed_data = RecordNSEC3::parse( packet_begin, packet_end, pos, pos + data_length );
            break;
        case TYPE_NSEC3PARAM:
            parsed_data = RecordNSEC3PARAM::parse( packet_begin, packet_end, pos, pos + data_length );
            break;
        case TYPE_TLSA:
            parsed_data = RecordTLSA::parse( packet_begin, packet_end, pos, pos + data_length );
            break;
        case TYPE_TSIG:
            parsed_data = RecordTSIGData::parse( packet_begin, packet_end, pos, pos + data_length, sec.mDomainname );
            break;
        case TYPE_OPT:
            parsed_data = RecordOptionsData::parse( packet_begin, packet_end, pos, pos + data_length );
            break;
        default:
            std::ostringstream msg;
            msg << "not support type \"" << sec.mType << "\".";
            parsed_data = RecordRaw::parse( sec.mType, pos, pos + data_length );
        }
        pos += data_length;

        BOOST_LOG_TRIVIAL( trace ) << "dns.rr.parse: parsed resource record";

        sec.mRData = parsed_data;
        return ResourceRecordPair( sec, pos );
    }

    std::ostream &printHeader( std::ostream &os, const MessageInfo &packet )
    {
        os << "ID: " << packet.mID << "\t"
           << "Query/Response: " << ( packet.mQueryResponse == 0 ? "Query" : "Response" ) << "\t"
           << "OpCode:" << packet.mOpcode << "\t"
           << "Authoritative Answer:" << packet.mAuthoritativeAnswer << "\t"
           << "Truncation: " << packet.mTruncation << "\t"
           << "Recursion Desired: " << packet.mRecursionDesired << "\t"
           << "Recursion Available: " << packet.mRecursionAvailable << "\t"
           << "Checking Disabled: " << packet.mCheckingDisabled << "\t"
           << "Response Code: " << responseCodeToString( packet.mResponseCode ) << "\t";

        return os;
    }

    std::string classCodeToString( Class c )
    {
        std::string res;
        switch ( c ) {
        case CLASS_IN:
            res = "IN";
            break;
        case CLASS_CH:
            res = "CH";
            break;
        case CLASS_HS:
            res = "HS";
            break;
        case CLASS_NONE:
            res = "NONE";
            break;
        case CLASS_ANY:
            res = "ANY";
            break;
        default:
            res = boost::lexical_cast<std::string>( c );
        }

        return res;
    }

    std::string typeCodeToString( Type t )
    {
        std::string res;

        switch ( t ) {
        case TYPE_A:
            res = "A";
            break;
        case TYPE_NS:
            res = "NS";
            break;
        case TYPE_CNAME:
            res = "CNAME";
            break;
        case TYPE_NAPTR:
            res = "NAPTR";
            break;
        case TYPE_DNAME:
            res = "DNAME";
            break;
        case TYPE_WKS:
            res = "WKS";
            break;
        case TYPE_MX:
            res = "MX";
            break;
        case TYPE_TXT:
            res = "TXT";
            break;
        case TYPE_SPF:
            res = "SPF";
            break;
        case TYPE_SOA:
            res = "SOA";
            break;
        case TYPE_SIG:
            res = "SIG";
            break;
        case TYPE_KEY:
            res = "KEY";
            break;
        case TYPE_AAAA:
            res = "AAAA";
            break;
        case TYPE_NXT:
            res = "NXT";
            break;
        case TYPE_OPT:
            res = "OPT";
            break;
        case TYPE_DS:
            res = "DS";
            break;
        case TYPE_RRSIG:
            res = "RRSIG";
            break;
        case TYPE_DNSKEY:
            res = "DNSKEY";
            break;
        case TYPE_NSEC:
            res = "NSEC";
            break;
        case TYPE_NSEC3:
            res = "NSEC3";
            break;
        case TYPE_NSEC3PARAM:
            res = "NSEC3PARAM";
            break;
        case TYPE_TLSA:
            res = "TLSA";
            break;
        case TYPE_TSIG:
            res = "TSIG";
            break;
        case TYPE_TKEY:
            res = "TKEY";
            break;
        case TYPE_IXFR:
            res = "IXFR";
            break;
        case TYPE_AXFR:
            res = "AXFR";
            break;
        case TYPE_ANY:
            res = "ANY";
            break;
        case TYPE_CAA:
            res = "CAA";
            break;
        case TYPE_SRV:
            res = "SRV";
            break;
        default:
            res = boost::lexical_cast<std::string>( t );
        }
        return res;
    }

    std::string responseCodeToString( uint8_t rcode )
    {
        std::string res;

        const char *rcode2str[] = {
            "NoError   No Error",
            "FormErr   Format Error",
            "ServFail  Server Failure",
            "NXDomain  Non-Existent Domain",
            "NotImp    Not Implemented",
            "Refused   Query Refused",
            "YXDomain  Name Exists when it should not",
            "YXRRSet   RR Set Exists when it should not",
            "NXRRSet   RR Set that should exist does not",
            "NotAuth   Server Not Authoritative for zone",
            "NotZone   Name not contained in zone",
            "11        available for assignment",
            "12        available for assignment",
            "13        available for assignment",
            "14        available for assignment",
            "15        available for assignment",
            "BADVERS   Bad OPT Version",
            "BADSIG    TSIG Signature Failure",
            "BADKEY    Key not recognized",
            "BADTIME   Signature out of time window",
            "BADMODE   Bad TKEY Mode",
            "BADNAME   Duplicate key name",
            "BADALG    Algorithm not supported",
        };

        if ( rcode < sizeof( rcode2str ) / sizeof( char * ) )
            res = rcode2str[ rcode ];
        else
            res = "n         available for assignment";

        return res;
    }

    Type stringToTypeCode( const std::string &t )
    {
        if ( t == "A" )
            return TYPE_A;
        if ( t == "AAAA" )
            return TYPE_AAAA;
        if ( t == "NS" )
            return TYPE_NS;
        if ( t == "CNAME" )
            return TYPE_CNAME;
        if ( t == "NAPTR" )
            return TYPE_NAPTR;
        if ( t == "DNAME" )
            return TYPE_DNAME;
        if ( t == "WKS" )
            return TYPE_WKS;
        if ( t == "MX" )
            return TYPE_MX;
        if ( t == "TXT" )
            return TYPE_TXT;
        if ( t == "SPF" )
            return TYPE_SPF;
        if ( t == "SOA" )
            return TYPE_SOA;
        if ( t == "SIG" )
            return TYPE_SIG;
        if ( t == "KEY" )
            return TYPE_KEY;
        if ( t == "NXT" )
            return TYPE_NXT;
        if ( t == "OPT" )
            return TYPE_OPT;
        if ( t == "DS" )
            return TYPE_DS;
        if ( t == "RRSIG" )
            return TYPE_RRSIG;
        if ( t == "DNSKEY" )
            return TYPE_DNSKEY;
        if ( t == "NSEC" )
            return TYPE_NSEC;
        if ( t == "NSEC3" )
            return TYPE_NSEC3;
        if ( t == "NSEC3PARAM" )
            return TYPE_NSEC3PARAM;
        if ( t == "TLSA" )
            return TYPE_TLSA;
        if ( t == "TSIG" )
            return TYPE_TSIG;
        if ( t == "TKEY" )
            return TYPE_TKEY;
        if ( t == "IXFR" )
            return TYPE_IXFR;
        if ( t == "AXFR" )
            return TYPE_AXFR;
        if ( t == "ANY" )
            return TYPE_ANY;
        if ( t == "CAA" )
            return TYPE_CAA;
        if ( t == "SRV" )
            return TYPE_SRV;

        throw std::runtime_error( "unknown type \"" + t + "\"" );
    }


    std::ostream &operator<<( std::ostream &os, const OptPseudoRecord &opt )
    {
        os << "Domainname: " << opt.mDomainname << "\t"
           << "PayloadSize: " << opt.mPayloadSize << "\t"
           << "RCode: " << (uint32_t)opt.mRCode << "\t"
           << "Version: " << (uint32_t)opt.mVersion << "\t"
           << "DOBIt: " << (uint32_t)opt.mDOBit << "\t"
           << "Options: " << opt.mOptions->toString();

        return os;
    }

    std::ostream &operator<<( std::ostream &os, const MessageInfo &res )
    {
        os << "ID: " << res.mID << "\t"
           << "Query/Response: " << ( res.mQueryResponse ? "Response" : "Query" ) << "\t"
           << "OpCode:" << (uint32_t)res.mOpcode << "\t"
           << "Authoritative Answer: " << res.mAuthoritativeAnswer << "\t"
           << "Truncation: " << res.mTruncation << "\t"
           << "Recursion Desired: " << res.mRecursionDesired << "\t"
           << "Recursion Available: " << res.mRecursionAvailable << "\t"
           << "Checking Disabled: " << res.mCheckingDisabled << "\t"
           << "Response Code: " << responseCodeToString( res.mResponseCode ) << "\t";

        for ( auto q : res.mQuestionSection )
            os << "Query:" << "\t" << q.mDomainname << "\t" << classCodeToString( q.mClass ) << "\t"
               << typeCodeToString( q.mType ) << ", ";
        for ( auto a : res.mAnswerSection )
            os << "Answer:" << "\t" << a.mDomainname << "\t" << a.mTTL << "\t" << classCodeToString( a.mClass ) << "\t"
               << typeCodeToString( a.mType ) << "\t" << a.mRData->toString() << ", ";
        for ( auto a : res.mAuthoritySection )
            os << "Authority:" << "\t" << a.mDomainname << "\t" << a.mTTL << "\t" << classCodeToString( a.mClass )
               << "\t" << typeCodeToString( a.mType ) << "\t" << a.mRData->toString() << ", ";
        for ( auto a : res.mAdditionalSection )
            os << "Additional:" << "\t" << a.mDomainname << "\t" << a.mTTL << "\t" << classCodeToString( a.mClass )
               << "\t" << typeCodeToString( a.mType ) << "\t" << a.mRData->toString() << ", ";
        if ( res.isEDNS0() ) {
            os << res.mOptPseudoRR << "\t";
        }
        return os;
    }

    std::string RecordRaw::toZone() const
    {
        std::string hex;
        encodeToHex( mData, hex );
        return hex;
    }

    std::string RecordRaw::toString() const
    {
        std::ostringstream os;
        os << "type: RAW(" << mRRType << "), data: ";

        for ( unsigned int i = 0; i < mData.size(); i++ ) {
            os << std::hex << (unsigned int)mData[ i ] << " ";
        }
        return os.str();
    }

    void RecordRaw::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        message.pushBuffer( mData );
    }

    void RecordRaw::outputCanonicalWireFormat( WireFormat &message ) const
    {
        message.pushBuffer( mData );
    }

    RDATAPtr RecordRaw::parse( Type type, const uint8_t *begin, const uint8_t *end )
    {
        return RDATAPtr( new RecordRaw( type, PacketData( begin, end ) ) );
    }

    RecordA::RecordA( uint32_t addr ) : mSinAddr( addr )
    {
    }

    RecordA::RecordA( const std::string &addr )
    {
        in_addr a = convertAddressStringToBinary( addr );
        std::memcpy( &mSinAddr, &a, sizeof( mSinAddr ) );
    }

    std::string RecordA::toZone() const
    {
        return toString();
    }

    std::string RecordA::toString() const
    {
        char buf[ 256 ];
        std::snprintf( buf,
                       sizeof( buf ),
                       "%d.%d.%d.%d",
                       *( reinterpret_cast<const uint8_t *>( &mSinAddr ) ),
                       *( reinterpret_cast<const uint8_t *>( &mSinAddr ) + 1 ),
                       *( reinterpret_cast<const uint8_t *>( &mSinAddr ) + 2 ),
                       *( reinterpret_cast<const uint8_t *>( &mSinAddr ) + 3 ) );
        return std::string( buf );
    }

    void RecordA::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        outputCanonicalWireFormat( message );
    }

    void RecordA::outputCanonicalWireFormat( WireFormat &message ) const
    {
        message.push_back( ( mSinAddr >> 0 ) & 0xff );
        message.push_back( ( mSinAddr >> 8 ) & 0xff );
        message.push_back( ( mSinAddr >> 16 ) & 0xff );
        message.push_back( ( mSinAddr >> 24 ) & 0xff );
    }

    std::string RecordA::getAddress() const
    {
        return toString();
    }

    RDATAPtr RecordA::parse( const uint8_t *begin, const uint8_t *end )
    {
        if ( end - begin != 4 )
            throw FormatError( "invalid A Record length" );
        return RDATAPtr( new RecordA( *( reinterpret_cast<const uint32_t *>( begin ) ) ) );
    }

    RecordAAAA::RecordAAAA( const uint8_t *addr )
    {
        std::memcpy( mSinAddr, addr, sizeof( mSinAddr ) );
    }

    RecordAAAA::RecordAAAA( const std::string &addr )
    {
        in_addr a = convertAddressStringToBinary( addr );
        std::memcpy( &mSinAddr, &a, sizeof( mSinAddr ) );
    }

    std::string RecordAAAA::toZone() const
    {
        return toString();
    }

    std::string RecordAAAA::toString() const
    {
        std::stringstream buff;
        buff << std::hex << (uint32_t)mSinAddr[ 0 ];
        for ( unsigned int i = 1; i < sizeof( mSinAddr ); i++ ) {
            buff << ":" << (uint32_t)mSinAddr[ i ];
        }
        return buff.str();
    }

    void RecordAAAA::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        outputCanonicalWireFormat( message );
    }

    void RecordAAAA::outputCanonicalWireFormat( WireFormat &message ) const
    {
        message.pushBuffer( reinterpret_cast<const uint8_t *>( &mSinAddr ),
                            reinterpret_cast<const uint8_t *>( &mSinAddr ) + sizeof( mSinAddr ) );
    }

    std::string RecordAAAA::getAddress() const
    {
        return toString();
    }

    RDATAPtr RecordAAAA::parse( const uint8_t *begin, const uint8_t *end )
    {
        if ( end - begin != 16 )
            throw FormatError( "invalid AAAA Record length" );
        return RDATAPtr( new RecordAAAA( begin ) );
    }

    RecordWKS::RecordWKS( uint32_t addr, uint8_t proto, const std::vector<Type> &b )
        : mSinAddr( addr ), mProtocol( proto ), mBitmap( b )
    {
    }

    std::string RecordWKS::toZone() const
    {
        return toString();
    }

    std::string RecordWKS::toString() const
    {
        char buf[ 256 ];
        std::snprintf( buf,
                       sizeof( buf ),
                       "%d.%d.%d.%d",
                       *( reinterpret_cast<const uint8_t *>( &mSinAddr ) ),
                       *( reinterpret_cast<const uint8_t *>( &mSinAddr ) + 1 ),
                       *( reinterpret_cast<const uint8_t *>( &mSinAddr ) + 2 ),
                       *( reinterpret_cast<const uint8_t *>( &mSinAddr ) + 3 ) );
        std::ostringstream os;
        os << buf << " " << (int)mProtocol << " ";
        for ( unsigned int i = 0; i < mBitmap.size(); i++ )
            if ( mBitmap[ i ] )
                os << "1";
            else
                os << "0";
        return os.str();
    }

    void RecordWKS::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        outputCanonicalWireFormat( message );
    }

    void RecordWKS::outputCanonicalWireFormat( WireFormat &message ) const
    {
        message.push_back( ( mSinAddr >> 0 ) & 0xff );
        message.push_back( ( mSinAddr >> 8 ) & 0xff );
        message.push_back( ( mSinAddr >> 16 ) & 0xff );
        message.push_back( ( mSinAddr >> 24 ) & 0xff );
        message.push_back( mProtocol );

        PacketData buf( 256 * 256 / 8 );
        std::memset( &buf[ 0 ], 0, buf.size() );
        unsigned int max_byte_index = 0;
        for ( unsigned int i = 0; i < mBitmap.size(); i++ ) {
            unsigned int byte_index = mBitmap[ i ] / 8;
            unsigned int bit_index  = mBitmap[ i ] % 8;
            buf[ byte_index ] |= ( 1 << bit_index );

            max_byte_index = std::max( max_byte_index, byte_index );
        }
        buf.resize( max_byte_index + 1 );

        message.pushBuffer( buf );
    }

    std::string RecordWKS::getAddress() const
    {
        return toString();
    }

    RDATAPtr RecordWKS::parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end )
    {
        if ( rdata_end - rdata_begin < 5 )
            throw FormatError( "too short size for WKS" );
        const uint8_t *pos = rdata_begin;

        uint32_t          addr  = get_bytes<uint32_t>( &pos );
        uint8_t           proto = get_bytes<uint8_t>( &pos );
        std::vector<Type> bitmap;

        for ( unsigned int i = 0; pos < rdata_end; i++, pos++ ) {
            for ( int j = 0; j < 8; j++ )
                if ( *pos & ( 1 << j ) )
                    bitmap.push_back( 256 * i + j );
        }
        return RDATAPtr( new RecordWKS( addr, proto, bitmap ) );
    }

    RecordNS::RecordNS( const Domainname &name ) : mDomainname( name )
    {
    }

    std::string RecordNS::toZone() const
    {
        return toString();
    }

    std::string RecordNS::toString() const
    {
        return mDomainname.toString();
    }

    uint32_t RecordNS::size( OffsetDB &offset_db, uint32_t begin ) const
    {
        return offset_db.getOutputWireFormatSize( mDomainname, begin );
    }

    void RecordNS::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        offset_db.outputWireFormat( mDomainname, message );
    }

    void RecordNS::outputCanonicalWireFormat( WireFormat &message ) const
    {
        mDomainname.outputCanonicalWireFormat( message );
    }

    RDATAPtr RecordNS::parse( const uint8_t *packet_begin,
                              const uint8_t *packet_end,
                              const uint8_t *rdata_begin,
                              const uint8_t *rdata_end )
    {
        Domainname name;
        Domainname::parsePacket( name, packet_begin, packet_end, rdata_begin );
        return RDATAPtr( new RecordNS( name ) );
    }

    RecordMX::RecordMX( uint16_t priority, const Domainname &name ) : mPriority( priority ), mDomainname( name )
    {
    }

    std::string RecordMX::toZone() const
    {
        return toString();
    }

    std::string RecordMX::toString() const
    {
        std::ostringstream os;
        os << mPriority << " " << mDomainname.toString();
        return os.str();
    }

    uint32_t RecordMX::size( OffsetDB &offset_db, uint32_t begin ) const
    {
        return sizeof( uint16_t ) + offset_db.getOutputWireFormatSize( mDomainname, begin );
    }

    void RecordMX::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        message.pushUInt16HtoN( mPriority );
        offset_db.outputWireFormat( mDomainname, message );
    }

    void RecordMX::outputCanonicalWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( mPriority );
        mDomainname.outputCanonicalWireFormat( message );
    }

    RDATAPtr RecordMX::parse( const uint8_t *packet_begin,
                              const uint8_t *packet_end,
                              const uint8_t *rdata_begin,
                              const uint8_t *rdata_end )
    {
        if ( rdata_end - rdata_begin < 3 )
            throw FormatError( "too few length for MX record," );
        const uint8_t *pos      = rdata_begin;
        uint16_t       priority = get_bytes<uint16_t>( &pos );

        Domainname name;
        Domainname::parsePacket( name, packet_begin, packet_end, pos );
        return RDATAPtr( new RecordMX( priority, name ) );
    }

    RecordTXT::RecordTXT( const std::string &d )
    {
        mData.push_back( d );
    }

    RecordTXT::RecordTXT( const std::vector<std::string> &d ) : mData( d )
    {
    }

    std::string RecordTXT::toZone() const
    {
        return toString();
    }


    std::string RecordTXT::toString() const
    {
        std::ostringstream os;
        for ( unsigned int i = 0; i < mData.size(); i++ ) {
            os << "\"" << mData[ i ] << "\" ";
        }

        return os.str();
    }

    void RecordTXT::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        outputCanonicalWireFormat( message );
    }

    void RecordTXT::outputCanonicalWireFormat( WireFormat &message ) const
    {
        for ( unsigned int i = 0; i < mData.size(); i++ ) {
            message.push_back( mData[ i ].size() & 0xff );
            for ( unsigned int j = 0; j < mData[ i ].size(); j++ )
                message.push_back( mData[ i ][ j ] );
        }
    }


    uint32_t RecordTXT::size() const
    {
        uint16_t s = 0;
        for ( auto i = mData.begin(); i != mData.end(); i++ ) {
            s++;
            s += i->size();
        }
        return s;
    }

    RDATAPtr RecordTXT::parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end )
    {
        if ( rdata_end - rdata_begin < 1 )
            throw FormatError( "too few length for TXT record" );
        const uint8_t           *pos = rdata_begin;
        std::vector<std::string> txt_data;

        while ( pos < rdata_end ) {
            uint8_t length = get_bytes<uint8_t>( &pos );
            if ( pos + length > rdata_end )
                throw FormatError( "bad charactor-code length" );
            txt_data.push_back( std::string( pos, pos + length ) );
            pos += length;
        }
        return RDATAPtr( new RecordTXT( txt_data ) );
    }

    RecordSPF::RecordSPF( const std::string &d )
    {
        data.push_back( d );
    }

    RecordSPF::RecordSPF( const std::vector<std::string> &d ) : data( d )
    {
    }

    std::string RecordSPF::toZone() const
    {
        return toString();
    }

    std::string RecordSPF::toString() const
    {
        std::ostringstream os;
        for ( unsigned int i = 0; i < data.size(); i++ ) {
            os << "\"" << data[ i ] << "\" ";
        }

        return os.str();
    }

    void RecordSPF::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        outputCanonicalWireFormat( message );
    }

    void RecordSPF::outputCanonicalWireFormat( WireFormat &message ) const
    {
        for ( unsigned int i = 0; i < data.size(); i++ ) {
            message.push_back( data[ i ].size() & 0xff );
            for ( unsigned int j = 0; j < data[ i ].size(); j++ )
                message.push_back( data[ i ][ j ] );
        }
    }

    uint32_t RecordSPF::size() const
    {
        uint16_t s = 0;
        for ( auto i = data.begin(); i != data.end(); i++ ) {
            s++;
            s += i->size();
        }
        return s;
    }

    RDATAPtr RecordSPF::parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end )
    {
        if ( rdata_end - rdata_begin < 1 )
            throw FormatError( "too few length for SPF record" );
        const uint8_t           *pos = rdata_begin;
        std::vector<std::string> txt_data;

        while ( pos < rdata_end ) {
            uint8_t length = get_bytes<uint8_t>( &pos );
            if ( pos + length > rdata_end )
                throw FormatError( "bad charactor-code length" );
            txt_data.push_back( std::string( pos, pos + length ) );
            pos += length;
        }
        return RDATAPtr( new RecordSPF( txt_data ) );
    }

    RecordCNAME::RecordCNAME( const Domainname &name ) : mDomainname( name )
    {
    }

    std::string RecordCNAME::toZone() const
    {
        return toString();
    }

    std::string RecordCNAME::toString() const
    {
        return mDomainname.toString();
    }

    uint32_t RecordCNAME::size( OffsetDB &offset_db, uint32_t begin ) const
    {
        return offset_db.getOutputWireFormatSize( mDomainname, begin );
    }

    void RecordCNAME::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        offset_db.outputWireFormat( mDomainname, message );
    }

    void RecordCNAME::outputCanonicalWireFormat( WireFormat &message ) const
    {
        mDomainname.outputCanonicalWireFormat( message );
    }


    RDATAPtr RecordCNAME::parse( const uint8_t *packet_begin,
                                 const uint8_t *packet_end,
                                 const uint8_t *rdata_begin,
                                 const uint8_t *rdata_end )
    {
        Domainname name;
        Domainname::parsePacket( name, packet_begin, packet_end, rdata_begin );
        return RDATAPtr( new RecordCNAME( name ) );
    }

    RecordNAPTR::RecordNAPTR( uint16_t           in_order,
                              uint16_t           in_preference,
                              const std::string &in_flags,
                              const std::string &in_services,
                              const std::string &in_regexp,
                              const Domainname  &in_replacement )
        : mOrder( in_order ), mPreference( in_preference ), mFlags( in_flags ), mServices( in_services ),
          mRegexp( in_regexp ), mReplacement( in_replacement )
    {
    }

    std::string RecordNAPTR::toZone() const
    {
        std::stringstream os;
        os << mOrder << " " << mPreference << " "
           << "\"" << mFlags << "\" "
           << "\"" << mServices << "\" "
           << "\"" << mRegexp << "\" "
           << "\"" << mReplacement << "\"";
        return os.str();
    }

    std::string RecordNAPTR::toString() const
    {
        std::stringstream os;
        os << "order: " << mOrder << ", preference: " << mPreference << "flags: " << mFlags
           << ", services: " << mServices << "regexp: " << mRegexp << ", replacement: " << mReplacement;
        return os.str();
    }

    void RecordNAPTR::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        outputCanonicalWireFormat( message );
    }

    void RecordNAPTR::outputCanonicalWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( mOrder );
        message.pushUInt16HtoN( mPreference );
        message.pushUInt8( mFlags.size() );
        message.pushBuffer( mFlags );
        message.pushUInt8( mRegexp.size() );
        message.pushBuffer( mRegexp );
        mReplacement.outputWireFormat( message );
    }

    uint32_t RecordNAPTR::size() const
    {
        return sizeof( mOrder ) + sizeof( mPreference ) + 1 + mFlags.size() + 1 + mRegexp.size() + mReplacement.size();
    }

    RDATAPtr RecordNAPTR::parse( const uint8_t *packet_begin,
                                 const uint8_t *packet_end,
                                 const uint8_t *rdata_begin,
                                 const uint8_t *rdata_end )
    {
        if ( rdata_end - rdata_begin < 2 + 2 + 1 + 1 + 1 + 1 )
            throw FormatError( "too short for NAPTR RR" );

        const uint8_t *pos           = rdata_begin;
        uint16_t       in_order      = ntohs( get_bytes<uint16_t>( &pos ) );
        uint16_t       in_preference = ntohs( get_bytes<uint16_t>( &pos ) );

        std::string in_flags, in_services, in_regexp;
        pos = parseCharacterString( pos, rdata_end, in_flags );
        pos = parseCharacterString( pos, rdata_end, in_services );
        pos = parseCharacterString( pos, rdata_end, in_regexp );

        Domainname in_replacement;
        Domainname::parsePacket( in_replacement, packet_begin, packet_end, pos );
        return RDATAPtr( new RecordNAPTR( in_order, in_preference, in_flags, in_services, in_regexp, in_replacement ) );
    }

    RecordDNAME::RecordDNAME( const Domainname &name ) : mDomainname( name )
    {
    }

    std::string RecordDNAME::toZone() const
    {
        return toString();
    }

    std::string RecordDNAME::toString() const
    {
        return mDomainname.toString();
    }

    uint32_t RecordDNAME::size( OffsetDB &offset_db, uint32_t begin ) const
    {
        return offset_db.getOutputWireFormatSize( mDomainname, begin );
    }

    void RecordDNAME::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        offset_db.outputWireFormat( mDomainname, message );
    }

    void RecordDNAME::outputCanonicalWireFormat( WireFormat &message ) const
    {
        mDomainname.outputCanonicalWireFormat( message );
    }


    RDATAPtr RecordDNAME::parse( const uint8_t *packet_begin,
                                 const uint8_t *packet_end,
                                 const uint8_t *rdata_begin,
                                 const uint8_t *rdata_end )
    {
        Domainname name;
        Domainname::parsePacket( name, packet_begin, packet_end, rdata_begin );
        return RDATAPtr( new RecordDNAME( name ) );
    }

    RecordSOA::RecordSOA( const Domainname &mn,
                          const Domainname &rn,
                          uint32_t          sr,
                          uint32_t          rf,
                          uint32_t          rt,
                          uint32_t          ex,
                          uint32_t          min )
        : mMName( mn ), mRName( rn ), mSerial( sr ), mRefresh( rf ), mRetry( rt ), mExpire( ex ), mMinimum( min )
    {
    }

    std::string RecordSOA::toZone() const
    {
        return toString();
    }

    std::string RecordSOA::toString() const
    {
        std::ostringstream soa_str;
        soa_str << mMName.toString() << " " << mRName.toString() << " " << mSerial << " " << mRefresh << " " << mRetry
                << " " << mExpire << " " << mMinimum;
        return soa_str.str();
    }

    uint32_t RecordSOA::size( OffsetDB &offset_db, uint32_t begin ) const
    {
        uint32_t size = 0;
        uint32_t pos  = begin;

        uint32_t mname_size = offset_db.getOutputWireFormatSize( mMName, pos );
        pos += mname_size;
        size += mname_size;

        uint32_t rname_size = offset_db.getOutputWireFormatSize( mRName, pos );
        pos += rname_size;
        size += rname_size;

        size = ( sizeof( mSerial ) + sizeof( mRefresh ) + sizeof( mRetry ) + sizeof( mExpire ) + sizeof( mMinimum ) );
        return size;
    }

    void RecordSOA::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        offset_db.outputWireFormat( mMName, message );
        offset_db.outputWireFormat( mRName, message );
        message.pushUInt32HtoN( mSerial );
        message.pushUInt32HtoN( mRefresh );
        message.pushUInt32HtoN( mRetry );
        message.pushUInt32HtoN( mExpire );
        message.pushUInt32HtoN( mMinimum );
    }

    void RecordSOA::outputCanonicalWireFormat( WireFormat &message ) const
    {
        mMName.outputCanonicalWireFormat( message );
        mRName.outputCanonicalWireFormat( message );
        message.pushUInt32HtoN( mSerial );
        message.pushUInt32HtoN( mRefresh );
        message.pushUInt32HtoN( mRetry );
        message.pushUInt32HtoN( mExpire );
        message.pushUInt32HtoN( mMinimum );
    }

    uint32_t RecordSOA::size() const
    {
        return mMName.size() + mRName.size() + sizeof( mSerial ) + sizeof( mRefresh ) + sizeof( mRetry ) +
               sizeof( mExpire ) + sizeof( mMinimum );
    }

    RDATAPtr RecordSOA::parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end )
    {
        Domainname     mname_result, rname_result;
        const uint8_t *pos = rdata_begin;
        pos                = Domainname::parsePacket( mname_result, packet_begin, packet_end, pos );
        pos                = Domainname::parsePacket( rname_result, packet_begin, packet_end, pos );
        if ( ( rdata_end - pos ) < ( sizeof( uint32_t ) * 5 ) )
            throw FormatError( "too short RDATA size for SOA" );
        uint32_t serial  = ntohl( get_bytes<uint32_t>( &pos ) );
        uint32_t refresh = ntohl( get_bytes<uint32_t>( &pos ) );
        uint32_t retry   = ntohl( get_bytes<uint32_t>( &pos ) );
        uint32_t expire  = ntohl( get_bytes<uint32_t>( &pos ) );
        uint32_t minimum = ntohl( get_bytes<uint32_t>( &pos ) );

        return RDATAPtr( new RecordSOA( mname_result, rname_result, serial, refresh, retry, expire, minimum ) );
    }

    std::string RecordAPL::toZone() const
    {
        return toString();
    }

    std::string RecordAPL::toString() const
    {
        std::ostringstream os;
        for ( auto i = mAPLEntries.begin(); i != mAPLEntries.end(); i++ ) {
            os << ( i->mNegation ? "!" : "" ) << i->mAddressFamily << ":" << printPacketData( i->mAFD ) << " ";
        }
        std::string result( os.str() );
        if ( result.size() > 0 )
            result.pop_back();
        return result;
    }

    void RecordAPL::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        outputCanonicalWireFormat( message );
    }

    void RecordAPL::outputCanonicalWireFormat( WireFormat &message ) const
    {
        for ( auto i = mAPLEntries.begin(); i != mAPLEntries.end(); i++ ) {
            message.pushUInt16HtoN( i->mAddressFamily );
            message.pushUInt8( i->mPrefix );
            message.pushUInt8( ( i->mNegation ? ( 1 << 7 ) : 0 ) | i->mAFD.size() );
            message.pushBuffer( i->mAFD );
        }
    }

    uint32_t RecordAPL::size() const
    {
        uint32_t s = 0;
        for ( auto i = mAPLEntries.begin(); i != mAPLEntries.end(); i++ ) {
            s += ( 2 + 1 + 1 + i->mAFD.size() );
        }
        return s;
    }

    RDATAPtr RecordAPL::parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end )
    {
        std::vector<APLEntry> entries;
        const uint8_t        *pos = rdata_begin;

        while ( pos < rdata_end ) {
            if ( rdata_end - pos < 4 )
                throw FormatError( "too short length of APL RDdata" );

            APLEntry entry;
            entry.mAddressFamily = ntohs( get_bytes<uint16_t>( &pos ) );
            entry.mPrefix        = get_bytes<uint8_t>( &pos );
            uint8_t neg_afd_len  = get_bytes<uint8_t>( &pos );
            entry.mNegation      = ( neg_afd_len & 0x01 ) == 0x01;
            uint8_t afd_length   = ( neg_afd_len >> 1 );

            if ( rdata_end - pos < afd_length )
                throw FormatError( "invalid AFD Data length" );

            PacketData in_afd;
            entry.mAFD.insert( in_afd.end(), pos, pos + afd_length );
            pos += afd_length;
            entries.push_back( entry );
        }

        return RDATAPtr( new RecordAPL( entries ) );
    }


    std::string RecordCAA::toZone() const
    {
        return toString();
    }

    std::string RecordCAA::toString() const
    {
        std::stringstream os;
        os << (uint32_t)mFlag << " \"" << mTag << "\" \"" << mValue << "\"";
        return os.str();
    }

    void RecordCAA::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        outputCanonicalWireFormat( message );
    }

    void RecordCAA::outputCanonicalWireFormat( WireFormat &message ) const
    {
        message.pushUInt8( mFlag );
        message.pushUInt8( mTag.size() );
        message.pushBuffer( mTag );
        message.pushBuffer( mValue );
    }

    uint32_t RecordCAA::size() const
    {
        return 1 + 1 + mTag.size() + mValue.size();
    }

    RDATAPtr RecordCAA::parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end )
    {
        if ( rdata_end - rdata_begin <= 1 + 1 )
            throw FormatError( "too short for CAA RR" );

        const uint8_t *pos      = rdata_begin;
        uint8_t        flag     = get_bytes<uint8_t>( &pos );
        uint8_t        tag_size = get_bytes<uint8_t>( &pos );

        std::string tag, value;
        tag.insert(
            tag.end(), reinterpret_cast<const uint8_t *>( pos ), reinterpret_cast<const uint8_t *>( pos ) + tag_size );
        pos += tag_size;
        if ( pos > rdata_end )
            throw FormatError( "invalid tag/value size for CAA" );
        value.insert( value.end(), reinterpret_cast<const uint8_t *>( pos ), rdata_end );

        return RDATAPtr( new RecordCAA( tag, value, flag ) );
    }


    RecordSRV::RecordSRV( uint16_t priority, uint16_t weight, uint16_t port, const Domainname &target )
        : mPriority( priority ), mWeight( weight ), mPort( port ), mTarget( target )
    {
    }

    std::string RecordSRV::toZone() const
    {
        return toString();
    }

    std::string RecordSRV::toString() const
    {
        std::ostringstream os;
        os << mPriority << " " << mWeight << " " << mPort << " " << mTarget.toString();
        return os.str();
    }

    uint32_t RecordSRV::size( OffsetDB &offset_db, uint32_t begin ) const
    {
        return sizeof( mPriority ) + sizeof( mWeight ) + sizeof( mPort ) +
               offset_db.getOutputWireFormatSize( mTarget, begin );
    }

    void RecordSRV::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        message.pushUInt16HtoN( mPriority );
        message.pushUInt16HtoN( mWeight );
        message.pushUInt16HtoN( mPort );
        offset_db.outputWireFormat( mTarget, message );
    }

    void RecordSRV::outputCanonicalWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( mPriority );
        message.pushUInt16HtoN( mWeight );
        message.pushUInt16HtoN( mPort );
        mTarget.outputCanonicalWireFormat( message );
    }

    RDATAPtr RecordSRV::parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end )
    {
        const uint8_t *pos = rdata_begin;

        if ( rdata_end - pos < 7 )
            throw FormatError( "too few length for SRV record," );
        uint16_t priority = get_bytes<uint16_t>( &pos );

        if ( rdata_end - pos < 5 )
            throw FormatError( "too few length for SRV record," );
        uint16_t weight = get_bytes<uint16_t>( &pos );

        if ( rdata_end - pos < 7 )
            throw FormatError( "too few length for SRV record," );
        uint16_t port = get_bytes<uint16_t>( &pos );

        Domainname name;
        Domainname::parsePacket( name, packet_begin, packet_end, pos );
        return RDATAPtr( new RecordSRV( priority, weight, port, name ) );
    }

    std::string RecordRRSIG::toZone() const
    {
        std::string signature_str;
        encodeToBase64( mSignature, signature_str );

        time_t expiration_time = mExpiration;
        time_t inception_time  = mInception;
        tm     expiration_tm, inception_tm;
        gmtime_r( &expiration_time, &expiration_tm );
        gmtime_r( &inception_time, &inception_tm );
        char expiration_str[ 256 ], inception_str[ 256 ];

        strftime( expiration_str, sizeof( expiration_str ), "%Y%m%d%H%M%S", &expiration_tm );
        strftime( inception_str, sizeof( inception_str ), "%Y%m%d%H%M%S", &inception_tm );

        std::ostringstream os;
        os << typeCodeToString( mTypeCovered ) << " " << (uint32_t)mAlgorithm << " " << (uint32_t)mLabelCount << " "
           << mOriginalTTL << " " << expiration_str << " " << inception_str << " " << mKeyTag << " "
           << mSigner.toString() << " " << signature_str;
        return os.str();
    }

    std::string RecordRRSIG::toString() const
    {
        std::string signature_str;
        encodeToBase64( mSignature, signature_str );

        std::ostringstream os;
        os << "Type Covered: " << typeCodeToString( mTypeCovered ) << ", "
           << "Algorithm: " << (uint32_t)mAlgorithm << ", "
           << "Label Count: " << (uint32_t)mLabelCount << ", "
           << "Original TTL: " << mOriginalTTL << ", "
           << "Expiration: " << mExpiration << ", "
           << "Inception: " << mInception << ", "
           << "Key Tag: " << mKeyTag << ", "
           << "signer: " << mSigner << ", "
           << "Signature: " << signature_str;
        return os.str();
    }

    void RecordRRSIG::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        outputCanonicalWireFormat( message );
    }

    void RecordRRSIG::outputCanonicalWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( mTypeCovered );
        message.pushUInt8( mAlgorithm );
        message.pushUInt8( mLabelCount );
        message.pushUInt32HtoN( mOriginalTTL );
        message.pushUInt32HtoN( mExpiration );
        message.pushUInt32HtoN( mInception );
        message.pushUInt16HtoN( mKeyTag );
        mSigner.outputCanonicalWireFormat( message );
        message.pushBuffer( mSignature );
    }

    std::string RecordDNSKEY::toZone() const
    {
        std::string public_key_str;
        encodeToBase64( mPublicKey, public_key_str );

        std::ostringstream os;
        os << ( mFlag == KSK ? "257" : "256" ) << " " << 3 << " " << (unsigned int)mAlgorithm << " " << public_key_str;
        return os.str();
    }


    std::string RecordDNSKEY::toString() const
    {
        std::string public_key_str;
        encodeToBase64( mPublicKey, public_key_str );

        std::ostringstream os;
        os << "KSK/ZSK: " << ( mFlag == KSK ? "KSK" : "ZSK" ) << ", "
           << "Protocal: " << 3 << ", "
           << "Algorithm: " << (unsigned int)mAlgorithm << ", "
           << "Public Key: " << public_key_str;
        return os.str();
    }

    void RecordDNSKEY::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        outputCanonicalWireFormat( message );
    }

    void RecordDNSKEY::outputCanonicalWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( mFlag );
        message.pushUInt8( 3 );
        message.pushUInt8( mAlgorithm );
        message.pushBuffer( mPublicKey );
    }

    RDATAPtr RecordDNSKEY::parse( const uint8_t *packet_begin,
                                  const uint8_t *packet_end,
                                  const uint8_t *rdata_begin,
                                  const uint8_t *rdata_end )
    {
        const uint8_t *pos = rdata_begin;
        uint16_t       f   = ntohs( get_bytes<uint16_t>( &pos ) );
        get_bytes<uint8_t>( &pos ); // skip unsed protocol field
        uint8_t    algo = get_bytes<uint8_t>( &pos );
        PacketData key;
        key.insert( key.end(), pos, rdata_end );

        return RDATAPtr( new RecordDNSKEY( f, algo, key ) );
    }

    std::string RecordDS::toZone() const
    {
        std::string digest_str;
        encodeToHex( mDigest, digest_str );

        std::ostringstream os;
        os << mKeyTag << " " << (unsigned int)mAlgorithm << " " << (unsigned int)mDigestType << " " << digest_str;
        return os.str();
    }

    std::string RecordDS::toString() const
    {
        std::string digest_str;
        encodeToHex( mDigest, digest_str );

        std::ostringstream os;
        os << "keytag: " << mKeyTag << ", "
           << "algorithm: " << (unsigned int)mAlgorithm << ", "
           << "digest type: " << (unsigned int)mDigestType << ", "
           << "digest: " << digest_str;
        return os.str();
    }

    void RecordDS::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        outputCanonicalWireFormat( message );
    }

    void RecordDS::outputCanonicalWireFormat( WireFormat &message ) const
    {
        std::string digest;
        encodeToHex( mDigest, digest );

        message.pushUInt16HtoN( mKeyTag );
        message.pushUInt8( mAlgorithm );
        message.pushUInt8( mDigestType );
        message.pushBuffer( mDigest );
    }

    RDATAPtr RecordDS::parse( const uint8_t *packet_begin,
                              const uint8_t *packet_end,
                              const uint8_t *rdata_begin,
                              const uint8_t *rdata_end )
    {
        if ( ( rdata_end - rdata_begin ) < ( 2 + 1 + 1 ) )
            throw FormatError( "too short RDATA for DS" );

        const uint8_t *pos   = rdata_begin;
        uint16_t       tag   = ntohs( get_bytes<uint16_t>( &pos ) );
        uint8_t        algo  = get_bytes<uint8_t>( &pos );
        uint8_t        dtype = get_bytes<uint8_t>( &pos );

        PacketData d;
        d.insert( d.end(), pos, rdata_end );

        return RDATAPtr( new RecordDS( tag, algo, dtype, d ) );
    }


    void NSECBitmapField::Window::add( Type t )
    {
        mTypes.push_back( t );
    }

    uint8_t NSECBitmapField::Window::getWindowSize() const
    {
        uint8_t max_bytes = 0;
        for ( Type t : mTypes ) {
            max_bytes = std::max<uint8_t>( max_bytes, typeToBitmapIndex( t ) / 8 + 1 );
        }
        return max_bytes;
    }

    uint32_t NSECBitmapField::Window::size() const
    {
        return getWindowSize() + 2;
    }

    void NSECBitmapField::Window::outputWireFormat( WireFormat &message ) const
    {
        uint8_t window_size = getWindowSize();
        message.pushUInt8( mIndex );
        message.pushUInt8( window_size );

        PacketData bitmaps;
        bitmaps.resize( window_size );
        for ( uint8_t &v : bitmaps )
            v = 0;
        for ( Type t : mTypes ) {
            uint8_t index = 7 - ( typeToBitmapIndex( t ) % 8 );
            uint8_t flag  = 1 << index;
            bitmaps.at( typeToBitmapIndex( t ) / 8 ) |= flag;
        }
        message.pushBuffer( bitmaps );
    }

    std::string NSECBitmapField::Window::toString() const
    {
        std::ostringstream os;
        for ( Type t : mTypes ) {
            os << typeCodeToString( t ) << ",";
        }

        std::string result( os.str() );
        if ( !result.empty() )
            result.pop_back();
        return result;
    }

    uint8_t NSECBitmapField::Window::typeToBitmapIndex( Type t )
    {
        return ( 0xff & t );
    }

    const uint8_t *NSECBitmapField::Window::parse( NSECBitmapField::Window &ref_win,
                                                   const uint8_t           *packet_begin,
                                                   const uint8_t           *begin,
                                                   const uint8_t           *end )
    {
        uint8_t window_index = *begin++;
        uint8_t window_size  = *begin++;
        if ( begin + window_size >= end )
            throw std::runtime_error( "Bad NSEC bitmap size" );

        ref_win.setIndex( window_index );
        for ( uint8_t bitmap_index = 0; bitmap_index / 8 < window_size; bitmap_index++ ) {
            uint8_t flag = 1 << ( ( bitmap_index - 1 ) % 8 );
            if ( *( begin + ( bitmap_index / 8 ) ) & flag ) {
                Type t = 0x0100 * window_index + bitmap_index;
                ref_win.add( t );
            }
        }
        return begin + window_size;
    }

    void NSECBitmapField::add( Type t )
    {
        uint8_t window_index = typeToWindowIndex( t );
        auto    window       = mWindows.find( window_index );
        if ( window == mWindows.end() ) {
            mWindows.insert( std::make_pair( window_index, Window( window_index ) ) );
        }
        window = mWindows.find( window_index );
        window->second.add( t );
    }

    void NSECBitmapField::addWindow( const NSECBitmapField::Window &win )
    {
        uint8_t window_index = win.getIndex();
        auto    window       = mWindows.find( window_index );
        if ( window == mWindows.end() ) {
            mWindows.insert( std::make_pair( window_index, win ) );
        } else {
            std::ostringstream os;
            os << "Bad NSEC record( mutiple window index \"" << (int)window_index << "\" is found.";
            throw std::runtime_error( os.str() );
        }
    }

    std::vector<Type> NSECBitmapField::getTypes() const
    {
        std::vector<Type> types;
        for ( auto bitmap : mWindows ) {
            types.insert( types.end(), bitmap.second.getTypes().begin(), bitmap.second.getTypes().end() );
        }
        return types;
    }

    std::string NSECBitmapField::toString() const
    {
        std::ostringstream os;
        for ( auto win : mWindows )
            os << win.second.toString() << " ";
        std::string result( os.str() );
        if ( !result.empty() )
            result.pop_back();
        return result;
    }

    uint32_t NSECBitmapField::size() const
    {
        uint32_t s = 0;
        for ( auto win : mWindows ) {
            s += win.second.size();
        }
        return s;
    }

    void NSECBitmapField::outputWireFormat( WireFormat &message ) const
    {
        for ( auto win : mWindows )
            win.second.outputWireFormat( message );
    }

    uint8_t NSECBitmapField::typeToWindowIndex( Type t )
    {
        return ( 0xff00 & t ) >> 8;
    }

    const uint8_t *NSECBitmapField::parse( NSECBitmapField &ref_bitmaps,
                                           const uint8_t   *packet_begin,
                                           const uint8_t   *packet_end,
                                           const uint8_t   *bitmap_begin,
                                           const uint8_t   *bitmap_end )
    {
        const uint8_t *pos = bitmap_begin;
        while ( pos < bitmap_end ) {
            NSECBitmapField::Window win;
            pos = NSECBitmapField::Window::parse( win, packet_begin, pos, bitmap_end );
            ref_bitmaps.addWindow( win );
        }
        return pos;
    }

    RecordNSEC::RecordNSEC( const Domainname &next, const std::vector<Type> &types ) : mNextDomainname( next )
    {
        for ( auto t : types ) {
            mBitmaps.add( t );
        }
    }

    std::string RecordNSEC::toZone() const
    {
        return toString();
    }

    std::string RecordNSEC::toString() const
    {
        return mNextDomainname.toString() + " " + mBitmaps.toString();
    }

    void RecordNSEC::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        outputCanonicalWireFormat( message );
    }

    void RecordNSEC::outputCanonicalWireFormat( WireFormat &message ) const
    {
        mNextDomainname.outputCanonicalWireFormat( message );
        mBitmaps.outputWireFormat( message );
    }

    uint32_t RecordNSEC::size() const
    {
        return mNextDomainname.size() + mBitmaps.size();
    }

    RDATAPtr RecordNSEC::parse( const uint8_t *packet_begin,
                                const uint8_t *packet_end,
                                const uint8_t *rdata_begin,
                                const uint8_t *rdata_end )
    {
        Domainname      next;
        const uint8_t  *pos = Domainname::parsePacket( next, packet_begin, packet_end, rdata_begin );
        NSECBitmapField bitmaps;
        NSECBitmapField::parse( bitmaps, packet_begin, packet_end, pos, rdata_end );
        return RDATAPtr( new RecordNSEC( next, bitmaps ) );
    }


    RecordNSEC3::RecordNSEC3( HashAlgorithm            algo,
                              uint8_t                  flag,
                              uint16_t                 iteration,
                              const PacketData        &salt,
                              const PacketData        &next_hash,
                              const std::vector<Type> &types )
        : mHashAlgorithm( algo ), mFlag( flag ), mIteration( iteration ), mSalt( salt ), mNextHash( next_hash )
    {
        for ( auto t : types ) {
            mBitmaps.add( t );
        }
    }

    std::string RecordNSEC3::toZone() const
    {
        return toString();
    }

    std::string RecordNSEC3::toString() const
    {
        std::string salt_string;
        if ( mSalt.size() == 0 )
            salt_string == "";
        else
            encodeToHex( mSalt, salt_string );

        std::string hash_string;
        if ( mNextHash.size() == 0 )
            hash_string == "";
        else
            encodeToBase32Hex( mNextHash, hash_string );

        std::stringstream os;
        os << (uint32_t)mHashAlgorithm << " " << (uint32_t)mFlag << " " << (uint32_t)mIteration << " " << salt_string
           << " " << hash_string << " " << mBitmaps.toString();
        return os.str();
    }

    void RecordNSEC3::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        outputCanonicalWireFormat( message );
    }

    void RecordNSEC3::outputCanonicalWireFormat( WireFormat &message ) const
    {
        message.pushUInt8( mHashAlgorithm );
        message.pushUInt8( mFlag );
        message.pushUInt16HtoN( mIteration );
        message.pushUInt8( mSalt.size() );
        message.pushBuffer( mSalt );
        message.pushUInt8( mNextHash.size() );
        message.pushBuffer( mNextHash );
        mBitmaps.outputWireFormat( message );
    }

    uint32_t RecordNSEC3::size() const
    {
        return +1                 // Hash Algorithm
               + 1                // Flags
               + 2                // Iteration
               + 1                // Salt size
               + mSalt.size()     // Salt
               + 1                // Next Hash size
               + mNextHash.size() // Hash
               + mBitmaps.size(); // Bitmaps
    }

    RDATAPtr RecordNSEC3::parse( const uint8_t *packet_begin,
                                 const uint8_t *packet_end,
                                 const uint8_t *rdata_begin,
                                 const uint8_t *rdata_end )
    {
        //                           alg flag itr ssize salt hsize hash bitmaps
        if ( rdata_end - rdata_begin < 1 + 1 + 2 + 1 + 1 + 1 + 1 + 3 ) {
            throw FormatError( "too few size for NSEC3" );
        }

        const uint8_t *pos       = rdata_begin;
        uint8_t        algo      = get_bytes<uint8_t>( &pos );
        uint8_t        flag      = get_bytes<uint8_t>( &pos );
        uint16_t       iteration = ntohs( get_bytes<uint16_t>( &pos ) );

        uint8_t salt_size = get_bytes<uint8_t>( &pos );
        if ( rdata_end - pos < salt_size + 1 + 1 + 3 ) {
            throw FormatError( "too few size for salt,hash,bitmaps of NSEC3" );
        }
        PacketData salt;
        salt.insert( salt.end(), pos, pos + salt_size );
        pos += salt_size;

        uint8_t next_hash_size = get_bytes<uint8_t>( &pos );
        if ( rdata_end - pos < next_hash_size + 3 ) {
            throw FormatError( "too few size for hash,bitmaps of NSEC3" );
        }
        PacketData next_hash;
        next_hash.insert( next_hash.end(), pos, pos + next_hash_size );
        pos += next_hash_size;

        NSECBitmapField bitmaps;
        NSECBitmapField::parse( bitmaps, packet_begin, packet_end, pos, rdata_end );
        return RDATAPtr( new RecordNSEC3( algo, flag, iteration, salt, next_hash, bitmaps ) );
    }

    RecordNSEC3PARAM::RecordNSEC3PARAM( HashAlgorithm algo, uint8_t flag, uint16_t iteration, const PacketData &salt )
        : mHashAlgorithm( algo ), mFlag( flag ), mIteration( iteration ), mSalt( salt )
    {
    }

    std::string RecordNSEC3PARAM::toZone() const
    {
        return toString();
    }

    std::string RecordNSEC3PARAM::toString() const
    {
        std::string salt_string;
        encodeToHex( mSalt, salt_string );

        std::stringstream os;
        os << (uint32_t)mHashAlgorithm << " " << (uint32_t)mFlag << " " << (uint32_t)mIteration << " " << salt_string;
        return os.str();
    }

    void RecordNSEC3PARAM::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        outputCanonicalWireFormat( message );
    }

    void RecordNSEC3PARAM::outputCanonicalWireFormat( WireFormat &message ) const
    {
        message.pushUInt8( mHashAlgorithm );
        message.pushUInt8( mFlag );
        message.pushUInt16HtoN( mIteration );
        message.pushUInt8( mSalt.size() );
        message.pushBuffer( mSalt );
    }

    uint32_t RecordNSEC3PARAM::size() const
    {
        return +1              // Hash Algorithm
               + 1             // Flags
               + 2             // Iteration
               + 1             // Salt size
               + mSalt.size(); // Salt
    }

    RDATAPtr RecordNSEC3PARAM::parse( const uint8_t *packet_begin,
                                      const uint8_t *packet_end,
                                      const uint8_t *rdata_begin,
                                      const uint8_t *rdata_end )
    {
        //                alg flag itr ssize salt
        if ( rdata_end - rdata_begin < 1 + 1 + 2 + 1 + 1 ) {
            throw FormatError( "too few size for NSEC3PARAM" );
        }
        const uint8_t *pos       = rdata_begin;
        uint8_t        algo      = get_bytes<uint8_t>( &pos );
        uint8_t        flag      = get_bytes<uint8_t>( &pos );
        uint16_t       iteration = ntohs( get_bytes<uint16_t>( &pos ) );

        uint8_t salt_size = get_bytes<uint8_t>( &pos );
        if ( rdata_end - pos < salt_size ) {
            throw FormatError( "too few size for salt" );
        }
        PacketData salt;
        salt.insert( salt.end(), pos, pos + salt_size );
        pos += salt_size;
        return RDATAPtr( new RecordNSEC3PARAM( algo, flag, iteration, salt ) );
    }


    std::string RecordTLSA::toZone() const
    {
        return toString();
    }

    std::string RecordTLSA::toString() const
    {
        std::string data;
        encodeToHex( mData, data );

        std::stringstream os;
        os << (uint32_t)mUsage << " " << (uint32_t)mSelector << " " << (uint32_t)mMatchingType << " " << data;

        return os.str();
    }

    void RecordTLSA::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        outputCanonicalWireFormat( message );
    }

    void RecordTLSA::outputCanonicalWireFormat( WireFormat &message ) const
    {
        message.pushUInt8( mUsage );
        message.pushUInt8( mSelector );
        message.pushUInt8( mMatchingType );
        message.pushBuffer( mData );
    }

    uint32_t RecordTLSA::size() const
    {
        return +1              // Usage
               + 1             // Selector
               + 1             // MatchingType
               + mData.size(); // Certificate Association Data
    }

    RDATAPtr RecordTLSA::parse( const uint8_t *packet_begin,
                                const uint8_t *packet_end,
                                const uint8_t *rdata_begin,
                                const uint8_t *rdata_end )
    {
        if ( rdata_end - rdata_begin < 1 + 1 + 1 + 1 ) {
            throw FormatError( "too few size for TLSA" );
        }
        const uint8_t *pos           = rdata_begin;
        uint8_t        usage         = get_bytes<uint8_t>( &pos );
        uint8_t        selector      = get_bytes<uint8_t>( &pos );
        uint8_t        matching_type = get_bytes<uint8_t>( &pos );

        PacketData data;
        data.insert( data.end(), pos, packet_end );
        return RDATAPtr( new RecordTLSA( usage, selector, matching_type, data ) );
    }

    std::string RecordOptionsData::toString() const
    {
        std::ostringstream os;

        for ( auto option : mOptions )
            os << option->toString() << ", ";

        return os.str();
    }


    uint32_t RecordOptionsData::size() const
    {
        uint32_t rr_size = 0;
        for ( auto option : mOptions ) {
            rr_size += 2;              // Option-Code
            rr_size += 2;              // Option-Data Length
            rr_size += option->size(); // OPtion-Data
        }
        return rr_size;
    }

    void RecordOptionsData::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        outputCanonicalWireFormat( message );
    }

    void RecordOptionsData::outputCanonicalWireFormat( WireFormat &message ) const
    {
        for ( auto option : mOptions ) {
            option->outputWireFormat( message );
        }
    }

    RDATAPtr RecordOptionsData::parse( const uint8_t *packet_begin,
                                       const uint8_t *packet_end,
                                       const uint8_t *rdata_begin,
                                       const uint8_t *rdata_end )
    {
        BOOST_LOG_TRIVIAL( trace ) << "dns.opt.parse: parse options data";

        const uint8_t *pos = rdata_begin;

        std::vector<OptPseudoRROptPtr> options;
        while ( pos < rdata_end ) {
            if ( rdata_end - pos < 4 ) {
                std::ostringstream os;
                os << "remains data " << rdata_end - pos << " is too few size.";
                throw FormatError( os.str() );
            }
            uint16_t option_code = ntohs( get_bytes<uint16_t>( &pos ) );
            uint16_t option_size = ntohs( get_bytes<uint16_t>( &pos ) );

            if ( option_size == 0 )
                continue;
            if ( pos + option_size > rdata_end ) {
                std::ostringstream os;
                os << "option data size is missmatch: option_size: " << option_size << "; remain size "
                   << rdata_end - pos;
                throw FormatError( os.str() );
            }

            switch ( option_code ) {
            case OPT_NSID:
                BOOST_LOG_TRIVIAL( trace ) << "dns.option.parse: parse NSID";
                options.push_back( NSIDOption::parse( pos, pos + option_size ) );
                break;
            case OPT_COOKIE:
                BOOST_LOG_TRIVIAL( trace ) << "dns.option.parse: parse COOKIE";
                options.push_back( CookieOption::parse( pos, pos + option_size ) );
                break;
            case OPT_CLIENT_SUBNET:
                BOOST_LOG_TRIVIAL( trace ) << "dns.option.parse: parse ClientSubnet";
                options.push_back( ClientSubnetOption::parse( pos, pos + option_size ) );
                break;
            case OPT_TCP_KEEPALIVE:
                BOOST_LOG_TRIVIAL( trace ) << "dns.option.parse: parse TCPKEEPALIVE";
                options.push_back( TCPKeepaliveOption::parse( pos, pos + option_size ) );
                break;
            case OPT_KEY_TAG:
                BOOST_LOG_TRIVIAL( trace ) << "dns.option.parse: parse KEYTAG";
                options.push_back( KeyTagOption::parse( pos, pos + option_size ) );
            case OPT_EXTEND_ERROR:
                BOOST_LOG_TRIVIAL( trace ) << "dns.option.parse: parse ExtendedDNSError";
                options.push_back( ExtendedErrorOption::parse( pos, pos + option_size ) );
            default:
                BOOST_LOG_TRIVIAL( trace ) << "dns.option.parse: unknown option " << option_code;
                break;
            }
            pos += option_size;
        }

        BOOST_LOG_TRIVIAL( trace ) << "dns.opiont.parsed: parse options data";
        return RDATAPtr( new RecordOptionsData( options ) );
    }

    ResourceRecord generateOptPseudoRecord( const OptPseudoRecord &opt )
    {
        ResourceRecord entry;
        entry.mDomainname = opt.mDomainname;
        entry.mType       = TYPE_OPT;
        entry.mClass      = opt.mPayloadSize;
        entry.mTTL        = ( ( (uint32_t)opt.mRCode ) << 24 ) + ( opt.mDOBit ? ( (uint32_t)1 << 15 ) : 0 );
        entry.mRData      = RDATAPtr( opt.mOptions->clone() );

        return entry;
    }

    OptPseudoRecord parseOPTPseudoRecord( const ResourceRecord &record )
    {
        OptPseudoRecord opt;
        opt.mDomainname  = record.mDomainname;
        opt.mPayloadSize = record.mClass;
        opt.mRCode       = record.mTTL >> 24;
        opt.mVersion     = 0xff & ( record.mTTL >> 16 );
        opt.mDOBit       = ( ( 1 << 7 ) & ( record.mTTL >> 8 ) ) ? true : false;
        opt.mOptions     = record.mRData;

        return opt;
    }

    std::string RAWOption::toString() const
    {
        std::string hex;
        encodeToHex( mData, hex );
        return hex;
    }

    void RAWOption::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( mCode );
        message.pushUInt16HtoN( mData.size() );
        message.pushBuffer( mData );
    }

    void NSIDOption::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( OPT_NSID );
        message.pushUInt16HtoN( mNSID.size() );
        message.pushBuffer( mNSID );
    }

    std::string NSIDOption::toString() const
    {
        return "NSID: ***";
    }

    OptPseudoRROptPtr NSIDOption::parse( const uint8_t *begin, const uint8_t *end )
    {
        std::string nsid( begin, end );
        return OptPseudoRROptPtr( new NSIDOption( nsid ) );
    }

    unsigned int ClientSubnetOption::getAddressSize( uint8_t prefix )
    {
        return ( prefix + 7 ) / 8;
    }

    void ClientSubnetOption::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( OPT_CLIENT_SUBNET );
        message.pushUInt16HtoN( size() );
        message.pushUInt16HtoN( mFamily );
        message.pushUInt8( mSourcePrefix );
        message.pushUInt8( mScopePrefix );

        if ( mFamily == IPv4 ) {
            uint8_t addr_buf[ 4 ];
            inet_pton( AF_INET, mAddress.c_str(), addr_buf );
            message.pushBuffer( addr_buf, addr_buf + getAddressSize( mSourcePrefix ) );
        } else {
            uint8_t addr_buf[ 16 ];
            inet_pton( AF_INET6, mAddress.c_str(), addr_buf );
            message.pushBuffer( addr_buf, addr_buf + getAddressSize( mSourcePrefix ) );
        }
    }

    uint16_t ClientSubnetOption::size() const
    {
        return 2 +                              // FAMILY
               1 +                              // SOURCE PREFIX-LENGTH
               1 +                              // SCOPE PREFIX-LENGTH
               getAddressSize( mSourcePrefix ); // ADDRESS
    }

    std::string ClientSubnetOption::toString() const
    {
        std::ostringstream os;
        os << "EDNSClientSubnet: "
           << "source:  " << (int)mSourcePrefix << "scope:   " << (int)mScopePrefix << "address: " << mAddress;
        return os.str();
    }

    OptPseudoRROptPtr ClientSubnetOption::parse( const uint8_t *begin, const uint8_t *end )
    {
        const uint8_t *pos = begin;

        uint16_t fam    = ntohs( get_bytes<uint16_t>( &pos ) );
        uint8_t  source = get_bytes<uint8_t>( &pos );
        uint8_t  scope  = get_bytes<uint8_t>( &pos );

        if ( fam == IPv4 ) {
            if ( source > 32 ) {
                throw FormatError( "invalid source prefix length of EDNS-Client-Subet" );
            }
            if ( scope > 32 ) {
                throw FormatError( "invalid scope prefix length of EDNS-Client-Subet" );
            }

            if ( source == 0 )
                return OptPseudoRROptPtr( new ClientSubnetOption( fam, source, scope, "0.0.0.0" ) );

            uint8_t addr_buf[ 4 ];
            char    addr_str[ INET_ADDRSTRLEN ];

            std::memset( addr_buf, 0, sizeof( addr_buf ) );
            std::memset( addr_str, 0, sizeof( addr_str ) );

            std::memcpy( addr_buf, pos, getAddressSize( source ) );
            inet_ntop( AF_INET, addr_buf, addr_str, sizeof( addr_buf ) );

            return OptPseudoRROptPtr( new ClientSubnetOption( fam, source, scope, addr_str ) );
        } else if ( fam == IPv6 ) {
            if ( source > 32 ) {
                throw FormatError( "invalid source prefix length of EDNS-Client-Subet" );
            }
            if ( scope > 32 ) {
                throw FormatError( "invalid scope prefix length of EDNS-Client-Subet" );
            }

            if ( source == 0 )
                return OptPseudoRROptPtr( new ClientSubnetOption( fam, source, scope, "::0" ) );

            uint8_t addr_buf[ 16 ];
            char    addr_str[ INET6_ADDRSTRLEN ];

            std::memset( addr_buf, 0, sizeof( addr_buf ) );
            std::memset( addr_str, 0, sizeof( addr_str ) );

            std::memcpy( addr_buf, pos, getAddressSize( source ) );
            inet_ntop( AF_INET6, addr_buf, addr_str, sizeof( addr_buf ) );

            return OptPseudoRROptPtr( new ClientSubnetOption( fam, source, scope, addr_str ) );
        } else {
            throw FormatError( "invalid family of EDNS-Client-Subet" );
        }
    }

    void CookieOption::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( OPT_COOKIE );
        message.pushUInt16HtoN( mClientCookie.size() + mServerCookie.size() );
        message.pushBuffer( mClientCookie );
        message.pushBuffer( mServerCookie );
    }

    uint16_t CookieOption::size() const
    {
        return mClientCookie.size() + // CLIENT COOKIE LENGTH
               mServerCookie.size();  // SERVER COOKIE LENGTH
    }

    std::string CookieOption::toString() const
    {
        std::string        client, server;
        std::ostringstream os;
        encodeToHex( mClientCookie, client );
        encodeToHex( mServerCookie, server );
        os << "DNSCookie: "
           << "client:  " << client << ", server:   " << server;
        return os.str();
    }

    OptPseudoRROptPtr CookieOption::parse( const uint8_t *begin, const uint8_t *end )
    {
        unsigned int size = end - begin;
        if ( size < 8 ) {
            return OptPseudoRROptPtr( new CookieOption( PacketData(), PacketData() ) );
        }

        PacketData client( begin, begin + 8 );
        PacketData server( begin + 8, end );

        return OptPseudoRROptPtr( new CookieOption( client, server ) );
    }

    void TCPKeepaliveOption::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( OPT_TCP_KEEPALIVE );
        message.pushUInt16HtoN( 2 );
        message.pushUInt16HtoN( mTimeout );
    }

    uint16_t TCPKeepaliveOption::size() const
    {
        return 2;
    }

    std::string TCPKeepaliveOption::toString() const
    {
        std::ostringstream os;
        os << "TCPKeepalive: " << mTimeout;
        return os.str();
    }

    OptPseudoRROptPtr TCPKeepaliveOption::parse( const uint8_t *begin, const uint8_t *end )
    {
        const uint8_t *pos = begin;

        unsigned int size = end - begin;
        if ( size != 2 ) {
            std::ostringstream os;
            os << "DNS TCPKeepalive length " << size << " must be 2.";
            throw FormatError( os.str() );
        }

        uint16_t timeout = ntohs( get_bytes<uint16_t>( &pos ) );
        return OptPseudoRROptPtr( new TCPKeepaliveOption( timeout ) );
    }

    std::string KeyTagOption::toString() const
    {
        std::ostringstream os;
        for ( auto tag : getTags() )
            os << tag << ", ";
        return os.str();
    }

    uint16_t KeyTagOption::size() const
    {
        return mTags.size() * 2; // Tags Size(2byte) * Tag Count
    }

    void KeyTagOption::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( OPT_KEY_TAG );
        message.pushUInt16HtoN( mTags.size() * 2 );
        for ( uint16_t tag : getTags() )
            message.pushUInt16HtoN( tag );
    }

    OptPseudoRROptPtr KeyTagOption::parse( const uint8_t *begin, const uint8_t *end )
    {
        const uint8_t *pos  = begin;
        uint16_t       size = end - begin;
        if ( size % 2 != 0 )
            throw FormatError( "bad option length for Key Tag Option" );
        uint16_t              tag_count = size / 2;
        std::vector<uint16_t> tags;
        tags.reserve( tag_count );
        for ( uint16_t i = 0; i < tag_count; i++ )
            tags.push_back( ntohs( get_bytes<uint16_t>( &pos ) ) );

        return OptPseudoRROptPtr( new KeyTagOption( tags ) );
    }

    std::string ExtendedErrorOption::toString() const
    {
        std::ostringstream os;
        os << "Error Code: " << mErrorCode << ", Extra Text: " << mExtraText;
        return os.str();
    }

    uint16_t ExtendedErrorOption::size() const
    {
        return 2 + mExtraText.size();
    }

    void ExtendedErrorOption::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( OPT_EXTEND_ERROR );
        message.pushUInt16HtoN( mErrorCode );
        message.pushBuffer( mExtraText );
    }

    OptPseudoRROptPtr ExtendedErrorOption::parse( const uint8_t *begin, const uint8_t *end )
    {
        const uint8_t *pos  = begin;
        uint16_t       size = end - begin;
        if ( size < 2 )
            throw FormatError( "bad option length for ExtendErrorOption" );
        uint16_t    code;
        std::string text;

        code = ntohs( get_bytes<uint16_t>( &pos ) );
        size -= 2;

        for ( uint16_t i = 0; i < size; i++ ) {
            text.push_back( get_bytes<uint8_t>( &pos ) );
        }

        return OptPseudoRROptPtr( new ExtendedErrorOption( code, text ) );
    }

    std::string ErrorReportingOption::toString() const
    {
        std::ostringstream os;
        os << "Agent Domain: " << mAgentDomain;
        return os.str();
    }

    uint16_t ErrorReportingOption::size() const
    {
        return mAgentDomain.size();
    }

    void ErrorReportingOption::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( OPT_ERROR_REPORTING );
        mAgentDomain.outputWireFormat( message );
    }

    OptPseudoRROptPtr ErrorReportingOption::parse( const uint8_t *begin, const uint8_t *end )
    {
        const uint8_t *pos  = begin;
        uint16_t       size = end - begin;

        Domainname agent_domain;
        Domainname::parsePacket( agent_domain, begin, end, begin );

        return OptPseudoRROptPtr( new ErrorReportingOption( agent_domain ) );
    }

    std::string RecordTKEY::toZone() const
    {
        return "";
    }

    std::string RecordTKEY::toString() const
    {
        return "";
    }

    uint32_t RecordTKEY::size() const
    {
        return mAlgorithm.size() + //
               4 +                 // inception
               4 +                 // expiration
               2 +                 // mode
               2 +                 // error
               2 +                 // key size
               mKey.size() +       // key
               2 +                 // other data size
               mOtherData.size();
    }

    void RecordTKEY::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        outputCanonicalWireFormat( message );
    }

    void RecordTKEY::outputCanonicalWireFormat( WireFormat &message ) const
    {
        mAlgorithm.outputCanonicalWireFormat( message );
        message.pushUInt32HtoN( mInception );
        message.pushUInt32HtoN( mExpiration );
        message.pushUInt16HtoN( mMode );
        message.pushUInt16HtoN( mError );
        message.pushUInt16HtoN( mKey.size() );
        message.pushBuffer( mKey );
        message.pushUInt16HtoN( mOtherData.size() );
        message.pushBuffer( mOtherData );
    }

    uint32_t RecordTSIGData::size() const
    {
        return mAlgorithm.size() + // ALGORITHM
               6 +                 // signed time
               2 +                 // FUDGE
               2 +                 // MAC SIZE
               mMAC.size() +       // MAC
               2 +                 // ORIGINAL ID
               2 +                 // ERROR
               2 +                 // OTHER LENGTH
               mOther.size();      // OTHER
    }

    void RecordTSIGData::outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const
    {
        outputCanonicalWireFormat( message );
    }

    void RecordTSIGData::outputCanonicalWireFormat( WireFormat &message ) const
    {
        uint32_t time_high = mSignedTime >> 16;
        uint32_t time_low  = ( ( 0xffff & mSignedTime ) << 16 ) + mFudge;

        mAlgorithm.outputCanonicalWireFormat( message );
        message.pushUInt32HtoN( time_high );
        message.pushUInt32HtoN( time_low );
        message.pushUInt16HtoN( mMAC.size() );
        message.pushBuffer( mMAC );
        message.pushUInt16HtoN( mOriginalID );
        message.pushUInt16HtoN( mError );
        message.pushUInt16HtoN( mOther.size() );
        message.pushBuffer( mOther );
    }

    std::string RecordTSIGData::toZone() const
    {
        std::string mac_str, other_str;
        encodeToBase64( mMAC, mac_str );
        encodeToBase64( mOther, other_str );

        time_t signed_time_t = mSignedTime;
        tm     signed_time_tm;
        gmtime_r( &signed_time_t, &signed_time_tm );
        char signed_time_str[ 256 ];

        strftime( signed_time_str, sizeof( signed_time_str ), "%Y%m%d%H%M%S", &signed_time_tm );

        std::ostringstream os;
        os << mKeyName.toString() << " " << mAlgorithm.toString() << " " << signed_time_str << " " << mFudge << " "
           << mac_str << " " << mOriginalID << " " << mError << " " << other_str;

        return os.str();
    }

    std::string RecordTSIGData::toString() const
    {
        std::ostringstream os;
        os << "key name: " << mKeyName << ", "
           << "algorigthm: " << mAlgorithm << ", "
           << "signed time: " << mSignedTime << ", "
           << "fudge: " << mFudge << ", "
           << "MAC: " << printPacketData( mMAC ) << ", "
           << "Original ID: " << mOriginalID << ", "
           << "Error: " << mError;

        return os.str();
    }

    RDATAPtr RecordTSIGData::parse( const uint8_t    *packet_begin,
                                    const uint8_t    *packet_end,
                                    const uint8_t    *rdata_begin,
                                    const uint8_t    *rdata_end,
                                    const Domainname &key_name )
    {
        const uint8_t *pos = rdata_begin;

        Domainname algorithm;
        pos = Domainname::parsePacket( algorithm, packet_begin, packet_end, pos );

        if ( rdata_end - pos < 8 + 4 )
            throw FormatError( "too short message for TSIG RR" );
        uint64_t time_high = ntohl( get_bytes<uint32_t>( &pos ) );
        uint32_t time_low  = ntohl( get_bytes<uint32_t>( &pos ) );

        if ( rdata_end - pos < 8 )
            throw FormatError( "too short message for TSIG RR" );
        uint64_t signed_time = ( time_high << 16 ) + ( time_low >> 16 );
        uint16_t fudge       = time_low;

        if ( rdata_end - pos < 2 )
            throw FormatError( "too short message for TSIG RR" );
        uint16_t mac_size = ntohs( get_bytes<uint16_t>( &pos ) );
        if ( rdata_end - pos > mac_size )
            throw FormatError( "too short message for TSIG RR" );
        PacketData mac;
        mac.insert( mac.end(), pos, pos + mac_size );
        pos += mac_size;

        if ( rdata_end - pos < 2 + 2 )
            throw FormatError( "too short message for TSIG RR" );
        uint16_t original_id = ntohs( get_bytes<uint16_t>( &pos ) );
        uint16_t error       = ntohs( get_bytes<uint16_t>( &pos ) );
        if ( pos >= rdata_end )
            throw FormatError( "too short message for TSIG RR" );

        if ( rdata_end - pos < 2 )
            throw FormatError( "too short message for TSIG RR" );
        uint16_t other_length = ntohs( get_bytes<uint16_t>( &pos ) );
        if ( pos + other_length > rdata_end )
            throw FormatError( "too short message for TSIG RR" );
        PacketData other;
        other.insert( other.end(), pos, pos + other_length );
        pos += other_length;

        return RDATAPtr(
            new RecordTSIGData( key_name, algorithm, signed_time, fudge, mac, original_id, error, other ) );
    }

    struct TSIGHash {
        Domainname name;
        Domainname algorithm;
        uint64_t   signed_time;
        uint16_t   fudge;
        uint16_t   error;
        uint16_t   other_length;
        PacketData other;

        void     outputWireFormat( WireFormat &message ) const;
        uint32_t size() const;
    };

    uint32_t TSIGHash::size() const
    {
        return name.size() + 2 + 4 + algorithm.size() + 6 + 2 + 2 + 2 + other.size();
    }


    void TSIGHash::outputWireFormat( WireFormat &message ) const
    {
        name.outputCanonicalWireFormat( message );
        algorithm.outputCanonicalWireFormat( message );

        uint32_t time_high = signed_time >> 16;
        uint32_t time_low  = ( ( 0xffff & signed_time ) << 16 ) + fudge;

        message.pushUInt16HtoN( CLASS_ANY );
        message.pushUInt32HtoN( 0 );
        algorithm.outputCanonicalWireFormat( message );
        message.pushUInt32HtoN( time_high );
        message.pushUInt32HtoN( time_low );
        message.pushUInt16HtoN( error );
        message.pushUInt16HtoN( other_length );
        message.pushBuffer( other );
    }


    PacketData getTSIGMAC( const TSIGInfo &tsig_info, const PacketData &message, const PacketData &query_mac )
    {
        PacketData   mac( EVP_MAX_MD_SIZE );
        unsigned int mac_size = EVP_MAX_MD_SIZE;

        WireFormat hash_target;
        hash_target.pushBuffer( query_mac );
        PacketData hash_data = query_mac;

        PacketData         presigned_message = message;
        PacketHeaderField *h                 = reinterpret_cast<PacketHeaderField *>( &presigned_message[ 0 ] );
        h->id                                = htons( tsig_info.mOriginalID );
        hash_target.pushBuffer( presigned_message );

        TSIGHash tsig_hash;
        tsig_hash.name         = tsig_info.mName;
        tsig_hash.algorithm    = tsig_info.mAlgorithm;
        tsig_hash.signed_time  = tsig_info.mSignedTime;
        tsig_hash.fudge        = tsig_info.mFudge;
        tsig_hash.error        = tsig_info.mError;
        tsig_hash.other_length = tsig_info.mOther.size();
        tsig_hash.other        = tsig_info.mOther;
        tsig_hash.outputWireFormat( hash_target );

        PacketData ht = hash_target.get();
        HMAC( EVP_get_digestbyname( "md5" ),
              &tsig_info.mKey[ 0 ],
              tsig_info.mKey.size(),
              reinterpret_cast<const unsigned char *>( &ht[ 0 ] ),
              hash_data.size(),
              reinterpret_cast<unsigned char *>( &mac[ 0 ] ),
              &mac_size );
        EVP_cleanup();
        mac.resize( mac_size );

        return mac;
    }

    void addTSIGResourceRecord( const TSIGInfo   &tsig_info,
                                WireFormat       &message,
                                const PacketData &query_mac,
                                OffsetDB         &offset_db )
    {
        PacketData mac = getTSIGMAC( tsig_info, message.get(), query_mac );

        ResourceRecord entry;
        entry.mDomainname = tsig_info.mName;
        entry.mType       = TYPE_TSIG;
        entry.mClass      = CLASS_ANY;
        entry.mTTL        = 0;
        entry.mRData      = RDATAPtr( new RecordTSIGData( tsig_info.mName,
                                                     tsig_info.mAlgorithm,
                                                     tsig_info.mSignedTime,
                                                     tsig_info.mFudge,
                                                     mac,
                                                     tsig_info.mOriginalID,
                                                     tsig_info.mError,
                                                     tsig_info.mOther ) );

        PacketData         packet  = message.get();
        PacketHeaderField *header  = reinterpret_cast<PacketHeaderField *>( &packet[ 0 ] );
        uint16_t           adcount = ntohs( header->additional_infomation_count );
        adcount++;
        header->additional_infomation_count = htons( adcount );

        message.clear();
        message.pushBuffer( packet );
        generateResourceRecord( entry, message, offset_db, false );
    }

    bool
    verifyTSIGResourceRecord( const TSIGInfo &tsig_info, const MessageInfo &packet_info, const WireFormat &message )
    {
        PacketData hash_data = message.get();

        PacketHeaderField *header = reinterpret_cast<PacketHeaderField *>( &hash_data[ 0 ] );
        header->id                = htons( tsig_info.mOriginalID );
        uint16_t adcount          = ntohs( header->additional_infomation_count );
        if ( adcount < 1 ) {
            throw FormatError( "adcount of message with TSIG record must not be 0" );
        }
        header->additional_infomation_count = htons( adcount - 1 );

        const uint8_t *pos = &hash_data[ 0 ];
        pos += sizeof( PacketHeaderField );

        // skip question section
        for ( auto q : packet_info.mQuestionSection )
            pos = parseQuestion( &hash_data[ 0 ], &hash_data[ 0 ] + hash_data.size(), pos ).second;

        // skip answer section
        for ( auto r : packet_info.mAnswerSection )
            pos = parseResourceRecord( &hash_data[ 0 ], &hash_data[ 0 ] + hash_data.size(), pos ).second;

        // skip authority section
        for ( auto r : packet_info.mAuthoritySection )
            pos = parseResourceRecord( &hash_data[ 0 ], &hash_data[ 0 ] + hash_data.size(), pos ).second;
        // SKIP NON TSIG RECORD IN ADDITIONAL SECTION
        bool is_found_tsig = false;
        for ( auto r : packet_info.mAdditionalSection ) {
            ResourceRecordPair parsed_rr_pair =
                parseResourceRecord( &hash_data[ 0 ], &hash_data[ 0 ] + hash_data.size(), pos );
            if ( parsed_rr_pair.first.mType == TYPE_TSIG ) {
                is_found_tsig = true;
                break;
            } else {
                pos = parsed_rr_pair.second;
            }
        }

        if ( !is_found_tsig ) {
            throw FormatError( "not found TSIG RR" );
        }
        // REMOVE TSIG RR( TSIG MUST BE FINAL RR IN MESSAGE )
        hash_data.resize( pos - &hash_data[ 0 ] );

        PacketData mac = getTSIGMAC( tsig_info, hash_data, PacketData() );
        return mac == tsig_info.mMAC;
    }
} // namespace dns
