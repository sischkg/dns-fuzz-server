#ifndef DNS_HPP
#define DNS_HPP

#include "domainname.hpp"
#include "utils.hpp"
#include <boost/cstdint.hpp>
#include <boost/shared_ptr.hpp>
#include <deque>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace dns
{
    typedef std::vector<uint8_t>::iterator       PacketIterator;
    typedef std::vector<uint8_t>::const_iterator ConstPacketIterator;

    typedef uint8_t Opcode;
    const Opcode    OPCODE_QUERY  = 0;
    const Opcode    OPCODE_NOTIFY = 4;
    const Opcode    OPCODE_UPDATE = 5;

    typedef uint16_t Class;
    const Class      CLASS_IN      = 1;
    const Class      CLASS_CH      = 3;
    const Class      CLASS_HS      = 4;
    const Class      CLASS_NONE    = 254;
    const Class      CLASS_ANY     = 255;
    const Class      UPDATE_NONE   = 254;
    const Class      UPDATE_EXIST  = 255;
    const Class      UPDATE_ADD    = 1;
    const Class      UPDATE_DELETE = 255;

    typedef uint16_t Type;
    const Type       TYPE_A          = 1;
    const Type       TYPE_NS         = 2;
    const Type       TYPE_CNAME      = 5;
    const Type       TYPE_SOA        = 6;
    const Type       TYPE_WKS        = 11;
    const Type       TYPE_MX         = 15;
    const Type       TYPE_TXT        = 16;
    const Type       TYPE_SIG        = 24;
    const Type       TYPE_KEY        = 25;
    const Type       TYPE_AAAA       = 28;
    const Type       TYPE_NXT        = 30;
    const Type       TYPE_SRV        = 33;
    const Type       TYPE_NAPTR      = 35;
    const Type       TYPE_DNAME      = 39;
    const Type       TYPE_OPT        = 41;
    const Type       TYPE_APL        = 42;
    const Type       TYPE_DS         = 43;
    const Type       TYPE_RRSIG      = 46;
    const Type       TYPE_NSEC       = 47;
    const Type       TYPE_DNSKEY     = 48;
    const Type       TYPE_NSEC3      = 50;
    const Type       TYPE_NSEC3PARAM = 51;
    const Type       TYPE_TLSA       = 52;
    const Type       TYPE_SPF        = 99;
    const Type       TYPE_TKEY       = 249;
    const Type       TYPE_TSIG       = 250;
    const Type       TYPE_IXFR       = 251;
    const Type       TYPE_AXFR       = 252;
    const Type       TYPE_ANY        = 255;
    const Type       TYPE_CAA        = 257;

    typedef int32_t TTL;

    typedef uint16_t OptType;
    const OptType    OPT_NSID            = 3;
    const OptType    OPT_CLIENT_SUBNET   = 8;
    const OptType    OPT_COOKIE          = 10;
    const OptType    OPT_TCP_KEEPALIVE   = 11;
    const OptType    OPT_KEY_TAG         = 14;
    const OptType    OPT_EXTEND_ERROR    = 15;
    const OptType    OPT_ERROR_REPORTING = 18;

    typedef uint8_t    ResponseCode;
    const ResponseCode NO_ERROR       = 0;
    const ResponseCode NXRRSET        = 0;
    const ResponseCode FORMAT_ERROR   = 1;
    const ResponseCode SERVER_ERROR   = 2;
    const ResponseCode NAME_ERROR     = 3;
    const ResponseCode NXDOMAIN       = 3;
    const ResponseCode NOT_IMPLEENTED = 4;
    const ResponseCode REFUSED        = 5;
    const ResponseCode BADSIG         = 16;
    const ResponseCode BADKEY         = 17;
    const ResponseCode BADTIME        = 18;

    typedef uint16_t        ExtendedErrorCode;
    const ExtendedErrorCode EDE_OTHER                        = 0;
    const ExtendedErrorCode EDE_UNSUPPORTED_DNSKEY_ALGORITHM = 1;
    const ExtendedErrorCode EDE_UNSUPPORTED_DS_DIGEST_TYPE   = 2;
    const ExtendedErrorCode EDE_STALE_ANSWER                 = 3;
    const ExtendedErrorCode EDE_FORGED_ANSWER                = 4;
    const ExtendedErrorCode EDE_DNSSEC_INDETERMINATE         = 5;
    const ExtendedErrorCode EDE_DNSSEC_BOGUS                 = 6;
    const ExtendedErrorCode EDE_SIGNATURE_EXPIRED            = 7;
    const ExtendedErrorCode EDE_SIGNATURE_NOT_YET_VALID      = 8;
    const ExtendedErrorCode EDE_DNSKEY_MISSING               = 9;
    const ExtendedErrorCode EDE_RRSIGS_MISSING               = 10;
    const ExtendedErrorCode EDE_NO_ZONE_KEY_BIT_SET          = 11;
    const ExtendedErrorCode EDE_NSEC_MISSING                 = 12;
    const ExtendedErrorCode EDE_CACHED_ERROR                 = 13;
    const ExtendedErrorCode EDE_NOT_READY                    = 14;
    const ExtendedErrorCode EDE_BLOCKED                      = 15;
    const ExtendedErrorCode EDE_CENSORED                     = 16;
    const ExtendedErrorCode EDE_FILTERED                     = 17;
    const ExtendedErrorCode EDE_PROHIBITED                   = 18;
    const ExtendedErrorCode EDE_STAKE_NXDOMAIN_ANSWER        = 19;
    const ExtendedErrorCode EDE_NOT_AUTHORITATIVE            = 20;
    const ExtendedErrorCode EDE_NOT_SUPPORTED                = 21;
    const ExtendedErrorCode EDE_NOT_REACHABLE_AUTHORITY      = 22;
    const ExtendedErrorCode EDE_NETWORK_ERROR                = 23;
    const ExtendedErrorCode EDE_INVALID_DATA                 = 24;

    class RDATA;
    typedef std::shared_ptr<RDATA>       RDATAPtr;
    typedef std::shared_ptr<const RDATA> ConstRDATAPtr;

    class RDATA
    {
    public:
        virtual ~RDATA()
        {
        }

        virtual std::string toZone() const                                                  = 0;
        virtual std::string toString() const                                                = 0;
        virtual void        outputWireFormat( WireFormat &message, OffsetDB &offset ) const = 0;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const          = 0;
        virtual Type        type() const                                                    = 0;
        virtual uint32_t    size() const                                                    = 0;
        virtual uint32_t    size( OffsetDB &, uint32_t begin ) const                        = 0;
        virtual RDATA      *clone() const                                                   = 0;
        std::ostream       &operator<<( std::ostream &os ) const
        {
            os << toString();
            return os;
        }
    };

    class RecordRaw : public RDATA
    {
    private:
        uint16_t   mRRType;
        PacketData mData;

    public:
        RecordRaw( uint8_t t, const PacketData &d ) : mRRType( t ), mData( d )
        {
        }

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual Type        type() const
        {
            return mRRType;
        }
        virtual uint32_t size() const
        {
            return mData.size();
        }
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const
        {
            return size();
        }
        virtual RecordRaw *clone() const
        {
            return new RecordRaw( mRRType, mData );
        }
        static RDATAPtr parse( Type type, const uint8_t *begin, const uint8_t *end );
    };

    class RecordA : public RDATA
    {
    private:
        uint32_t mSinAddr;

    public:
        RecordA( uint32_t in_sin_addr );
        RecordA( const std::string &in_address );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual Type        type() const
        {
            return TYPE_A;
        }
        virtual uint32_t size() const
        {
            return sizeof( mSinAddr );
        }
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const
        {
            return size();
        }
        virtual RecordA *clone() const
        {
            return new RecordA( mSinAddr );
        }

        std::string     getAddress() const;
        static RDATAPtr parse( const uint8_t *begin, const uint8_t *end );
    };

    class RecordAAAA : public RDATA
    {
    private:
        uint8_t mSinAddr[ 16 ];

    public:
        RecordAAAA( const uint8_t *sin_addr );
        RecordAAAA( const std::string &address );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual Type        type() const
        {
            return TYPE_AAAA;
        }
        virtual uint32_t size() const
        {
            return sizeof( mSinAddr );
        }
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const
        {
            return size();
        }
        virtual RecordAAAA *clone() const
        {
            return new RecordAAAA( mSinAddr );
        }

        std::string getAddress() const;

        static RDATAPtr parse( const uint8_t *begin, const uint8_t *end );
    };


    class RecordWKS : public RDATA
    {
    private:
        uint32_t          mSinAddr;
        uint8_t           mProtocol;
        std::vector<Type> mBitmap;

    public:
        RecordWKS( uint32_t sin_addr, uint8_t proto, const std::vector<Type> & );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual Type        type() const
        {
            return TYPE_WKS;
        }
        virtual uint32_t size() const
        {
            return sizeof( mSinAddr );
        }
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const
        {
            return size();
        }
        virtual RecordWKS *clone() const
        {
            return new RecordWKS( mSinAddr, mProtocol, mBitmap );
        }

        std::string getAddress() const;
        uint8_t     getProtocol() const
        {
            return mProtocol;
        }
        const std::vector<Type> &getBitmap() const
        {
            return mBitmap;
        }
        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };


    class RecordNS : public RDATA
    {
    private:
        Domainname mDomainname;

    public:
        RecordNS( const Domainname &name );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t    type() const
        {
            return TYPE_NS;
        }
        virtual uint32_t size() const
        {
            return mDomainname.size();
        }
        virtual uint32_t  size( OffsetDB &offset_db, uint32_t begin ) const;
        virtual RecordNS *clone() const
        {
            return new RecordNS( mDomainname );
        }
        const Domainname &getNameServer() const
        {
            return mDomainname;
        }

        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };

    class RecordMX : public RDATA
    {
    private:
        uint16_t   mPriority;
        Domainname mDomainname;

    public:
        RecordMX( uint16_t pri, const Domainname &name );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t    type() const
        {
            return TYPE_MX;
        }
        virtual uint32_t size() const
        {
            return sizeof( mPriority ) + mDomainname.size();
        }
        virtual uint32_t  size( OffsetDB &offset_db, uint32_t begin ) const;
        virtual RecordMX *clone() const
        {
            return new RecordMX( mPriority, mDomainname );
        }

        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };

    class RecordTXT : public RDATA
    {
    private:
        std::vector<std::string> mData;

    public:
        RecordTXT( const std::string &data );
        RecordTXT( const std::vector<std::string> &data );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t    type() const
        {
            return TYPE_TXT;
        }
        virtual uint32_t size() const;
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const
        {
            return size();
        }
        virtual RecordTXT *clone() const
        {
            return new RecordTXT( mData );
        }
        const std::vector<std::string> &getTexts() const
        {
            return mData;
        }

        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };

    class RecordSPF : public RDATA
    {
    private:
        std::vector<std::string> data;

    public:
        RecordSPF( const std::string &data );
        RecordSPF( const std::vector<std::string> &data );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t    type() const
        {
            return TYPE_SPF;
        }
        virtual uint32_t size() const;
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const
        {
            return size();
        }
        virtual RecordSPF *clone() const
        {
            return new RecordSPF( data );
        }

        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };

    class RecordCNAME : public RDATA
    {
    private:
        Domainname mDomainname;

    public:
        RecordCNAME( const Domainname &name );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t    type() const
        {
            return TYPE_CNAME;
        }
        virtual uint32_t size() const
        {
            return mDomainname.size();
        }
        virtual uint32_t     size( OffsetDB &offset_db, uint32_t begin ) const;
        virtual RecordCNAME *clone() const
        {
            return new RecordCNAME( mDomainname );
        }

        const Domainname &getCanonicalName() const
        {
            return mDomainname;
        }

        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };

    class RecordNAPTR : public RDATA
    {
    private:
        uint16_t    mOrder;
        uint16_t    mPreference;
        std::string mFlags;
        std::string mServices;
        std::string mRegexp;
        Domainname  mReplacement;

    public:
        RecordNAPTR( uint16_t           in_order,
                     uint16_t           in_preference,
                     const std::string &in_flags,
                     const std::string &in_services,
                     const std::string &in_regexp,
                     const Domainname  &in_replacement );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t    type() const
        {
            return TYPE_NAPTR;
        }
        virtual uint32_t size() const;
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const
        {
            return size();
        }
        virtual RecordNAPTR *clone() const
        {
            return new RecordNAPTR( mOrder, mPreference, mFlags, mServices, mRegexp, mReplacement );
        }

        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };

    class RecordDNAME : public RDATA
    {
    private:
        Domainname mDomainname;

    public:
        RecordDNAME( const Domainname &name );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t    type() const
        {
            return TYPE_DNAME;
        }
        virtual uint32_t size() const
        {
            return mDomainname.size();
        }
        virtual uint32_t  size( OffsetDB &offset_db, uint32_t begin ) const;
        const Domainname &getCanonicalName() const
        {
            return mDomainname;
        }

        virtual RecordDNAME *clone() const
        {
            return new RecordDNAME( mDomainname );
        }

        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };

    class RecordSOA : public RDATA
    {
    private:
        Domainname mMName;
        Domainname mRName;
        uint32_t   mSerial;
        uint32_t   mRefresh;
        uint32_t   mRetry;
        uint32_t   mExpire;
        uint32_t   mMinimum;

    public:
        RecordSOA( const Domainname &mname,
                   const Domainname &rname,
                   uint32_t          serial,
                   uint32_t          refresh,
                   uint32_t          retry,
                   uint32_t          expire,
                   uint32_t          minimum );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t    type() const
        {
            return TYPE_SOA;
        }
        virtual uint32_t size() const;
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const;

        const std::string getMName() const
        {
            return mMName.toString();
        }
        const std::string getRName() const
        {
            return mRName.toString();
        }
        virtual RecordSOA *clone() const
        {
            return new RecordSOA( mMName, mRName, mSerial, mRefresh, mRetry, mExpire, mMinimum );
        }

        uint32_t getSerial() const
        {
            return mSerial;
        }
        uint32_t getRefresh() const
        {
            return mRefresh;
        }
        uint32_t getRetry() const
        {
            return mRetry;
        }
        uint32_t getExpire() const
        {
            return mExpire;
        }
        uint32_t getMinimum() const
        {
            return mMinimum;
        }

        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };


    struct APLEntry {
        uint16_t   mAddressFamily;
        uint8_t    mPrefix;
        bool       mNegation;
        PacketData mAFD;
    };

    class RecordAPL : public RDATA
    {
    private:
        std::vector<APLEntry> mAPLEntries;

    public:
        static const uint16_t IPv4    = 1;
        static const uint16_t IPv6    = 2;
        static const uint16_t Invalid = 0xffff;

        RecordAPL( const std::vector<APLEntry> &in_apls ) : mAPLEntries( in_apls )
        {
        }

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t    type() const
        {
            return TYPE_APL;
        }
        virtual uint32_t size() const;
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const
        {
            return size();
        }
        virtual RecordAPL *clone() const
        {
            return new RecordAPL( mAPLEntries );
        }

        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };

    class RecordCAA : public RDATA
    {
    private:
        uint8_t     mFlag;
        std::string mTag;
        std::string mValue;

    public:
        static const uint8_t CRITICAL     = 1;
        static const uint8_t NOT_CRITICAL = 0;

        RecordCAA( const std::string &tag, const std::string &value, uint8_t flag = NOT_CRITICAL )
            : mFlag( flag ), mTag( tag ), mValue( value )
        {
        }

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t    type() const
        {
            return TYPE_CAA;
        }
        virtual uint32_t size() const;
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const
        {
            return size();
        }
        virtual RecordCAA *clone() const
        {
            return new RecordCAA( *this );
        }

        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };

    class RecordSRV : public RDATA
    {
    private:
        uint16_t   mPriority;
        uint16_t   mWeight;
        uint16_t   mPort;
        Domainname mTarget;

    public:
        RecordSRV( uint16_t pri, uint16_t weight, uint16_t port, const Domainname &target );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t    type() const
        {
            return TYPE_SRV;
        }
        virtual uint32_t size() const
        {
            return sizeof( mPriority ) + sizeof( mWeight ) + sizeof( mPort ) + mTarget.size();
        }
        virtual uint32_t   size( OffsetDB &offset_db, uint32_t begin ) const;
        virtual RecordSRV *clone() const
        {
            return new RecordSRV( mPriority, mWeight, mPort, mTarget );
        }

        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };


    class RecordRRSIG : public RDATA
    {
    private:
        Type       mTypeCovered;
        uint8_t    mAlgorithm;
        uint8_t    mLabelCount;
        TTL        mOriginalTTL;
        uint32_t   mExpiration;
        uint32_t   mInception;
        uint16_t   mKeyTag;
        Domainname mSigner;
        PacketData mSignature;

    public:
        static const uint16_t SIGNED_KEY = 1 << 7;
        static const uint8_t  RSAMD5     = 1;
        static const uint8_t  RSASHA1    = 5;
        static const uint8_t  RSASHA256  = 8;
        static const uint8_t  RSASHA512  = 10;

        RecordRRSIG( Type              t,
                     uint8_t           algo,
                     uint8_t           label,
                     TTL               ttl,
                     uint32_t          expire,
                     uint32_t          incept,
                     uint16_t          tag,
                     const Domainname &sign,
                     const PacketData &sig )
            : mTypeCovered( t ), mAlgorithm( algo ), mLabelCount( label ), mOriginalTTL( ttl ), mExpiration( expire ),
              mInception( incept ), mKeyTag( tag ), mSigner( sign ), mSignature( sig )
        {
        }

        Type getTypeCovered() const
        {
            return mTypeCovered;
        }
        uint8_t getAlgorithm() const
        {
            return mAlgorithm;
        }
        uint8_t getLabelCount() const
        {
            return mLabelCount;
        }
        TTL getOriginalTTL() const
        {
            return mOriginalTTL;
        }
        uint32_t getExpiration() const
        {
            return mExpiration;
        }
        uint32_t getInception() const
        {
            return mInception;
        }
        uint8_t getKeyTag() const
        {
            return mKeyTag;
        }
        const Domainname &getSigner() const
        {
            return mSigner;
        }
        const PacketData &getSignature() const
        {
            return mSignature;
        }

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint32_t    size() const
        {
            return 2 + // type_covered(uint16_t)
                   1 + // algorithm
                   1 + // label count
                   4 + // original ttl
                   4 + // expiration
                   4 + // inception
                   2 + // key tag
                   mSigner.size() + mSignature.size();
        }
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const
        {
            return size();
        }

        virtual uint16_t type() const
        {
            return TYPE_RRSIG;
        }
        virtual RecordRRSIG *clone() const
        {
            return new RecordRRSIG( mTypeCovered,
                                    mAlgorithm,
                                    mLabelCount,
                                    mOriginalTTL,
                                    mExpiration,
                                    mInception,
                                    mKeyTag,
                                    mSigner,
                                    mSignature );
        }

        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };


    class RecordDNSKEY : public RDATA
    {
    private:
        uint16_t   mFlag;
        uint8_t    mAlgorithm;
        PacketData mPublicKey;

    public:
        static const uint16_t SIGNED_KEY = 1 << 7;
        static const uint8_t  RSAMD5     = 1;
        static const uint8_t  RSASHA1    = 5;
        static const uint8_t  RSASHA256  = 8;
        static const uint8_t  RSASHA512  = 10;

        static const uint16_t KSK = 1 << 8;
        static const uint16_t ZSK = 0;

        RecordDNSKEY( uint16_t f, uint8_t algo, const PacketData &key )
            : mFlag( f ), mAlgorithm( algo ), mPublicKey( key )
        {
        }

        uint16_t getFlag() const
        {
            return mFlag;
        }
        uint8_t getAlgorithm() const
        {
            return mAlgorithm;
        }
        const PacketData getPublicKey() const
        {
            return mPublicKey;
        }

        virtual std::string toZone() const;
        virtual std::string toString() const;

        virtual void     outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void     outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint32_t size() const
        {
            return sizeof( mFlag ) + sizeof( mAlgorithm ) + 1 + mPublicKey.size();
        }
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const
        {
            return size();
        }

        virtual uint16_t type() const
        {
            return TYPE_DNSKEY;
        }

        virtual RecordDNSKEY *clone() const
        {
            return new RecordDNSKEY( mFlag, mAlgorithm, mPublicKey );
        }

        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };


    class RecordDS : public RDATA
    {
    private:
        uint16_t   mKeyTag;
        uint8_t    mAlgorithm;
        uint8_t    mDigestType;
        PacketData mDigest;

    public:
        RecordDS( uint16_t tag, uint8_t alg, uint8_t dtype, const PacketData &d )
            : mKeyTag( tag ), mAlgorithm( alg ), mDigestType( dtype ), mDigest( d )
        {
        }

        uint16_t getKeyTag() const
        {
            return mKeyTag;
        }
        uint8_t getAlgorighm() const
        {
            return mAlgorithm;
        }
        uint8_t getDigesType() const
        {
            return mDigestType;
        }
        PacketData getDigest() const
        {
            return mDigest;
        }

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint32_t    size() const
        {
            return sizeof( mKeyTag ) + sizeof( mAlgorithm ) + sizeof( mDigestType ) + mDigest.size();
        }
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const
        {
            return size();
        }

        virtual uint16_t type() const
        {
            return TYPE_DS;
        }

        virtual RecordDS *clone() const
        {
            return new RecordDS( mKeyTag, mAlgorithm, mDigestType, mDigest );
        }

        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };


    class NSECBitmapField
    {
    public:
        class Window
        {
        public:
            explicit Window( uint8_t i = 0 ) : mIndex( i )
            {
            }

            void setIndex( uint8_t i )
            {
                mIndex = i;
            }
            void        add( Type );
            uint32_t    size() const;
            void        outputWireFormat( WireFormat &message ) const;
            std::string toString() const;
            uint16_t    getIndex() const
            {
                return mIndex;
            }
            uint8_t                  getWindowSize() const;
            const std::vector<Type> &getTypes() const
            {
                return mTypes;
            }

            static const uint8_t *parse( Window        &ref_windown,
                                         const uint8_t *packet_begin,
                                         const uint8_t *bitmap_begin,
                                         const uint8_t *bitmap_end );

        private:
            uint16_t          mIndex;
            std::vector<Type> mTypes;

            static uint8_t typeToBitmapIndex( Type );
        };

        void              add( Type );
        void              addWindow( const Window &win );
        std::vector<Type> getTypes() const;

        std::string toString() const;
        uint32_t    size() const;
        void        outputWireFormat( WireFormat &message ) const;

        static const uint8_t *parse( NSECBitmapField &ref_bitmaps,
                                     const uint8_t   *packet_begin,
                                     const uint8_t   *packet_end,
                                     const uint8_t   *rdata_begin,
                                     const uint8_t   *rdata_end );

    private:
        std::map<uint8_t, Window> mWindows;

        static uint8_t typeToWindowIndex( Type );
    };

    class RecordNSEC : public RDATA
    {
    private:
        Domainname      mNextDomainname;
        NSECBitmapField mBitmaps;

    public:
        RecordNSEC( const Domainname &next, const NSECBitmapField &b ) : mNextDomainname( next ), mBitmaps( b )
        {
        }
        RecordNSEC( const Domainname &next, const std::vector<Type> &types );
        const Domainname &getNextDomainname() const
        {
            return mNextDomainname;
        }
        std::vector<Type> getTypes() const
        {
            return mBitmaps.getTypes();
        }

        virtual std::string toZone() const;
        virtual std::string toString() const;

        virtual void     outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void     outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint32_t size() const;
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const
        {
            return size();
        }
        virtual uint16_t type() const
        {
            return TYPE_NSEC;
        }
        virtual RecordNSEC *clone() const
        {
            return new RecordNSEC( mNextDomainname, mBitmaps );
        }

        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };

    class RecordNSEC3 : public RDATA
    {
    public:
        typedef uint8_t HashAlgorithm;

    private:
        HashAlgorithm   mHashAlgorithm;
        uint8_t         mFlag;
        uint16_t        mIteration;
        PacketData      mSalt;
        PacketData      mNextHash;
        NSECBitmapField mBitmaps;

    public:
        RecordNSEC3( HashAlgorithm            algo,
                     uint8_t                  flag,
                     uint16_t                 iteration,
                     const PacketData        &salt,
                     const PacketData        &next_hash,
                     const std::vector<Type> &bitmaps );
        RecordNSEC3( HashAlgorithm          algo,
                     uint8_t                flag,
                     uint16_t               iteration,
                     const PacketData      &salt,
                     const PacketData      &next_hash,
                     const NSECBitmapField &bitmaps )
            : mHashAlgorithm( algo ), mFlag( flag ), mIteration( iteration ), mSalt( salt ), mNextHash( next_hash ),
              mBitmaps( bitmaps )
        {
        }

        HashAlgorithm getHashAlgoritm() const
        {
            return mHashAlgorithm;
        }
        uint8_t getFlag() const
        {
            return mFlag;
        }
        uint16_t getIteration() const
        {
            return mIteration;
        }
        PacketData getSalt() const
        {
            return mSalt;
        }
        PacketData getNextHash() const
        {
            return mNextHash;
        }
        std::vector<Type> getTypes() const
        {
            return mBitmaps.getTypes();
        }

        virtual std::string toZone() const;
        virtual std::string toString() const;

        virtual void     outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void     outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint32_t size() const;
        virtual uint16_t type() const
        {
            return TYPE_NSEC3;
        }
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const
        {
            return size();
        }
        virtual RecordNSEC3 *clone() const
        {
            return new RecordNSEC3( mHashAlgorithm, mFlag, mIteration, mSalt, mNextHash, mBitmaps.getTypes() );
        }

        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };


    class RecordNSEC3PARAM : public RDATA
    {
    public:
        typedef uint8_t HashAlgorithm;

    private:
        HashAlgorithm mHashAlgorithm;
        uint8_t       mFlag;
        uint16_t      mIteration;
        PacketData    mSalt;

    public:
        RecordNSEC3PARAM( HashAlgorithm algo, uint8_t flag, uint16_t iteration, const PacketData &salt );

        HashAlgorithm getHashAlgoritm() const
        {
            return mHashAlgorithm;
        }
        uint8_t getFlag() const
        {
            return mFlag;
        }
        uint16_t getIteration() const
        {
            return mIteration;
        }
        PacketData getSalt() const
        {
            return mSalt;
        }

        virtual std::string toZone() const;
        virtual std::string toString() const;

        virtual void     outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const;
        virtual void     outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint32_t size() const;
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const
        {
            return size();
        }
        virtual uint16_t type() const
        {
            return TYPE_NSEC3PARAM;
        }
        virtual RecordNSEC3PARAM *clone() const
        {
            return new RecordNSEC3PARAM( mHashAlgorithm, mFlag, mIteration, mSalt );
        }

        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };


    class RecordTLSA : public RDATA
    {
    public:
        typedef uint8_t Usage;
        typedef uint8_t Selector;
        typedef uint8_t MatchingType;

    private:
        Usage                      mUsage;
        Selector                   mSelector;
        MatchingType               mMatchingType;
        const std::vector<uint8_t> mData;

    public:
        RecordTLSA( Usage usage, Selector selector, MatchingType type, const std::vector<uint8_t> &data )
            : mUsage( usage ), mSelector( selector ), mMatchingType( type ), mData( data )
        {
        }

        virtual std::string toZone() const;
        virtual std::string toString() const;

        virtual void     outputWireFormat( WireFormat &message, OffsetDB &offset_db ) const;
        virtual void     outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint32_t size() const;
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const
        {
            return size();
        }
        virtual uint16_t type() const
        {
            return TYPE_TLSA;
        }
        virtual RecordTLSA *clone() const
        {
            return new RecordTLSA( mUsage, mSelector, mMatchingType, mData );
        }

        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };

    const uint8_t PROTOCOL_TLS    = 0x01;
    const uint8_t PROTOCOL_MAIL   = 0x02;
    const uint8_t PROTOCOL_DNSSEC = 0x03;
    const uint8_t PROTOCOL_IPSEC  = 0x04;
    const uint8_t PROTOCOL_ANY    = 0xFF;

    const uint8_t ALGORITHM_DH = 0x02;

    class RecordKEY : public RecordDNSKEY
    {
    public:
        RecordKEY( uint16_t f, uint8_t a, const PacketData &p ) : RecordDNSKEY( f, a, p )
        {
        }

        virtual uint16_t type() const
        {
            return TYPE_KEY;
        }

        virtual RecordKEY *clone() const
        {
            return new RecordKEY( getFlag(), getAlgorithm(), getPublicKey() );
        }
    };


    class RecordSIG : public RecordRRSIG
    {
    public:
        RecordSIG( Type              t,
                   uint8_t           algo,
                   uint8_t           label,
                   uint32_t          ttl,
                   uint32_t          expire,
                   uint32_t          incept,
                   uint16_t          tag,
                   const Domainname &sign,
                   const PacketData &sig )
            : RecordRRSIG( t, algo, label, ttl, expire, incept, tag, sign, sig )
        {
        }

        virtual uint16_t type() const
        {
            return TYPE_SIG;
        }
        virtual RecordSIG *clone() const
        {
            return new RecordSIG( getTypeCovered(),
                                  getAlgorithm(),
                                  getLabelCount(),
                                  getOriginalTTL(),
                                  getExpiration(),
                                  getInception(),
                                  getKeyTag(),
                                  getSigner(),
                                  getSignature() );
        }
    };


    class RecordNXT : public RecordNSEC
    {
    public:
        RecordNXT( const Domainname &next, const NSECBitmapField &b ) : RecordNSEC( next, b )
        {
        }
        RecordNXT( const Domainname &next, const std::vector<Type> &types ) : RecordNSEC( next, types )
        {
        }

        virtual uint16_t type() const
        {
            return TYPE_NXT;
        }
        virtual RecordNXT *clone() const
        {
            return new RecordNXT( getNextDomainname(), getTypes() );
        }
    };

    class OptPseudoRROption
    {
    public:
        virtual ~OptPseudoRROption()
        {
        }
        virtual std::string        toString() const                       = 0;
        virtual void               outputWireFormat( WireFormat & ) const = 0;
        virtual uint16_t           code() const                           = 0;
        virtual uint16_t           size() const                           = 0;
        virtual OptPseudoRROption *clone() const                          = 0;
    };

    typedef std::shared_ptr<OptPseudoRROption> OptPseudoRROptPtr;

    class RAWOption : public OptPseudoRROption
    {
    private:
        uint16_t   mCode;
        PacketData mData;

    public:
        RAWOption( uint16_t in_code, const PacketData &in_data ) : mCode( in_code ), mData( in_data )
        {
        }

        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat & ) const;
        virtual uint16_t    code() const
        {
            return mCode;
        }
        virtual uint16_t size() const
        {
            return mData.size(); // OPTION DATA
        }
        virtual RAWOption *clone() const
        {
            return new RAWOption( mCode, mData );
        }
    };

    class NSIDOption : public OptPseudoRROption
    {
    private:
        std::string mNSID;

    public:
        NSIDOption( const std::string &id = "" ) : mNSID( id )
        {
        }

        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat & ) const;
        virtual uint16_t    code() const
        {
            return OPT_NSID;
        }
        virtual uint16_t size() const
        {
            return mNSID.size();
        }
        virtual NSIDOption *clone() const
        {
            return new NSIDOption( mNSID );
        }

        static OptPseudoRROptPtr parse( const uint8_t *begin, const uint8_t *end );
    };

    class ClientSubnetOption : public OptPseudoRROption
    {
    private:
        uint16_t    mFamily;
        uint8_t     mSourcePrefix;
        uint8_t     mScopePrefix;
        std::string mAddress;

        static unsigned int getAddressSize( uint8_t prefix );

    public:
        static const int IPv4 = 1;
        static const int IPv6 = 2;

        ClientSubnetOption( uint16_t fam, uint8_t source, uint8_t scope, const std::string &addr )
            : mFamily( fam ), mSourcePrefix( source ), mScopePrefix( scope ), mAddress( addr )
        {
        }

        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat & ) const;
        virtual uint16_t    code() const
        {
            return OPT_CLIENT_SUBNET;
        }
        virtual ClientSubnetOption *clone() const
        {
            return new ClientSubnetOption( mFamily, mSourcePrefix, mScopePrefix, mAddress );
        }
        virtual uint16_t size() const;

        static OptPseudoRROptPtr parse( const uint8_t *begin, const uint8_t *end );
    };

    class CookieOption : public OptPseudoRROption
    {
    private:
        PacketData mClientCookie;
        PacketData mServerCookie;

    public:
        CookieOption( const PacketData &client, const PacketData &server = PacketData() )
            : mClientCookie( client ), mServerCookie( server )
        {
        }

        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat & ) const;
        virtual uint16_t    code() const
        {
            return OPT_COOKIE;
        }
        virtual CookieOption *clone() const
        {
            return new CookieOption( mClientCookie, mServerCookie );
        }
        virtual uint16_t size() const;

        static OptPseudoRROptPtr parse( const uint8_t *begin, const uint8_t *end );
    };

    class TCPKeepaliveOption : public OptPseudoRROption
    {
    private:
        uint16_t mTimeout;

    public:
        TCPKeepaliveOption( uint16_t timeout ) : mTimeout( timeout )
        {
        }

        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat & ) const;
        virtual uint16_t    code() const
        {
            return OPT_TCP_KEEPALIVE;
        }
        virtual TCPKeepaliveOption *clone() const
        {
            return new TCPKeepaliveOption( mTimeout );
        }
        virtual uint16_t size() const;

        static OptPseudoRROptPtr parse( const uint8_t *begin, const uint8_t *end );
    };


    class KeyTagOption : public OptPseudoRROption
    {
    private:
        std::vector<uint16_t> mTags;

    public:
        KeyTagOption( std::vector<uint16_t> tags ) : mTags( tags )
        {
        }

        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat & ) const;
        virtual uint16_t    code() const
        {
            return OPT_KEY_TAG;
        }
        virtual KeyTagOption *clone() const
        {
            return new KeyTagOption( getTags() );
        }
        virtual uint16_t size() const;

        const std::vector<uint16_t> &getTags() const
        {
            return mTags;
        }

        static OptPseudoRROptPtr parse( const uint8_t *begin, const uint8_t *end );
    };

    class ExtendedErrorOption : public OptPseudoRROption
    {
    private:
        ExtendedErrorCode mErrorCode;
        std::string       mExtraText;

    public:
        ExtendedErrorOption( ExtendedErrorCode c, std::string text ) : mErrorCode( c ), mExtraText( text )
        {
        }

        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat & ) const;
        virtual uint16_t    code() const
        {
            return OPT_EXTEND_ERROR;
        }
        virtual ExtendedErrorOption *clone() const
        {
            return new ExtendedErrorOption( mErrorCode, mExtraText );
        }
        virtual uint16_t size() const;

        uint16_t getErrorCode() const
        {
            return mErrorCode;
        }
        std::string getExtraText() const
        {
            return mExtraText;
        }

        static OptPseudoRROptPtr parse( const uint8_t *begin, const uint8_t *end );
    };

    class ErrorReportingOption : public OptPseudoRROption
    {
    private:
        Domainname mAgentDomain;

    public:
        ErrorReportingOption( const Domainname &agent_domain ) : mAgentDomain( agent_domain )
        {
        }

        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat & ) const;
        virtual uint16_t    code() const
        {
            return OPT_EXTEND_ERROR;
        }
        virtual ErrorReportingOption *clone() const
        {
            return new ErrorReportingOption( mAgentDomain );
        }
        virtual uint16_t size() const;

        const Domainname getAgentDomain()
        {
            return mAgentDomain;
        }

        static OptPseudoRROptPtr parse( const uint8_t *begin, const uint8_t *end );
    };

    class RecordOptionsData : public RDATA
    {
    private:
        std::vector<OptPseudoRROptPtr> mOptions;

    public:
        RecordOptionsData( const std::vector<OptPseudoRROptPtr> &in_options = std::vector<OptPseudoRROptPtr>() )
        {
            for ( auto op : in_options )
                mOptions.push_back( OptPseudoRROptPtr( op->clone() ) );
        }

        RecordOptionsData( const RecordOptionsData &data )
        {
            for ( auto op : data.getOptions() )
                mOptions.push_back( OptPseudoRROptPtr( op->clone() ) );
        }

        RecordOptionsData &operator=( const RecordOptionsData &data )
        {
            mOptions.clear();
            for ( auto op : data.getOptions() )
                mOptions.push_back( OptPseudoRROptPtr( op->clone() ) );
            return *this;
        }

        void add( OptPseudoRROptPtr opt )
        {
            mOptions.push_back( opt );
        }
        virtual std::string toZone() const
        {
            return "";
        }
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &message, OffsetDB &offset ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t    type() const
        {
            return TYPE_OPT;
        }
        virtual uint32_t size() const;
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const
        {
            return size();
        }
        virtual RecordOptionsData *clone() const
        {
            return new RecordOptionsData( mOptions );
        }

        const std::vector<OptPseudoRROptPtr> &getOptions() const
        {
            return mOptions;
        }

        static RDATAPtr parse( const uint8_t *packet_begin,
                               const uint8_t *packet_end,
                               const uint8_t *rdata_begin,
                               const uint8_t *rdata_end );
    };

    struct OptPseudoRecord {
        Domainname mDomainname;
        uint16_t   mPayloadSize;
        uint8_t    mRCode;
        uint8_t    mVersion;
        bool       mDOBit;
        RDATAPtr   mOptions;

        OptPseudoRecord()
            : mDomainname( "." ), mPayloadSize( 1280 ), mRCode( 0 ), mDOBit( false ),
              mOptions( RDATAPtr( new RecordOptionsData ) )
        {
        }

        OptPseudoRecord( const OptPseudoRecord &opt )
            : mDomainname( opt.mDomainname ), mPayloadSize( opt.mPayloadSize ), mRCode( opt.mRCode ),
              mVersion( opt.mVersion ), mDOBit( opt.mDOBit )
        {
            if ( opt.mOptions )
                mOptions = RDATAPtr( opt.mOptions->clone() );
        }

        OptPseudoRecord &operator=( const OptPseudoRecord &rhs )
        {
            mDomainname  = rhs.mDomainname;
            mPayloadSize = rhs.mPayloadSize;
            mRCode       = rhs.mRCode;
            mVersion     = rhs.mVersion;
            mDOBit       = rhs.mDOBit;
            if ( rhs.mOptions )
                mOptions = RDATAPtr( rhs.mOptions->clone() );
            else
                mOptions = RDATAPtr( new RecordOptionsData );
            return *this;
        }
    };

    class RecordTKEY : public RDATA
    {
    public:
        Domainname mDomain;
        Domainname mAlgorithm;
        uint32_t   mInception;
        uint32_t   mExpiration;
        uint16_t   mMode;
        uint16_t   mError;
        PacketData mKey;
        PacketData mOtherData;

    public:
        RecordTKEY( const Domainname &dom    = Domainname(),
                    const Domainname &algo   = ( Domainname ) "HMAC-MD5.SIG-ALG.REG.INT",
                    uint32_t          incept = 0,
                    uint32_t          expire = 0,
                    uint16_t          m      = 0,
                    uint16_t          err    = 0,
                    PacketData        k      = PacketData(),
                    PacketData        other  = PacketData() )
            : mDomain( dom ), mAlgorithm( algo ), mInception( incept ), mExpiration( expire ), mMode( m ),
              mError( err ), mKey( k ), mOtherData( other )
        {
        }

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &, OffsetDB & ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t    type() const
        {
            return TYPE_TKEY;
        }
        virtual uint32_t size() const;
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const
        {
            return size();
        }
        virtual RecordTKEY *clone() const
        {
            return new RecordTKEY( mDomain, mDomain, mInception, mExpiration, mMode, mError, mKey, mOtherData );
        }
    };

    struct TSIGInfo {
        Domainname mName;
        PacketData mKey;
        Domainname mAlgorithm;
        PacketData mMAC;
        uint64_t   mSignedTime;
        uint16_t   mFudge;
        uint16_t   mOriginalID;
        uint16_t   mError;
        PacketData mOther;

        TSIGInfo()
            : mName(), mKey(), mAlgorithm( ( Domainname ) "HMAC-MD5.SIG-ALG.REG.INT" ), mMAC(), mSignedTime( 0 ),
              mFudge( 0 ), mOriginalID( 0 ), mError( 0 ), mOther()
        {
        }
    };

    class RecordTSIGData : public RDATA
    {
    public:
        Domainname mKeyName;
        Domainname mAlgorithm;
        uint64_t   mSignedTime;
        uint16_t   mFudge;
        PacketData mMAC;
        uint16_t   mOriginalID;
        uint16_t   mError;
        PacketData mOther;

    public:
        RecordTSIGData( const Domainname &in_key_name    = ( Domainname ) "",
                        const Domainname &in_algo        = ( Domainname ) "HMAC-MD5.SIG-ALG.REG.INT",
                        uint64_t          in_signed_time = 0,
                        uint16_t          in_fudge       = 0,
                        const PacketData &in_mac         = PacketData(),
                        uint16_t          in_original_id = 0,
                        uint16_t          in_error       = 0,
                        const PacketData &in_other       = PacketData() )
            : mKeyName( in_key_name ), mAlgorithm( in_algo ), mSignedTime( in_signed_time ), mFudge( in_fudge ),
              mMAC( in_mac ), mOriginalID( in_original_id ), mError( in_error ), mOther( in_other )
        {
        }

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat &, OffsetDB & ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t    type() const
        {
            return TYPE_TSIG;
        }
        virtual uint32_t size() const;
        virtual uint32_t size( OffsetDB &offset_db, uint32_t begin ) const
        {
            return size();
        }
        virtual RecordTSIGData *clone() const
        {
            return new RecordTSIGData( mKeyName, mAlgorithm, mSignedTime, mFudge, mMAC, mOriginalID, mError, mOther );
        }
        static RDATAPtr parse( const uint8_t    *packet_begin,
                               const uint8_t    *packet_end,
                               const uint8_t    *rdata_begin,
                               const uint8_t    *rdata_end,
                               const Domainname &key_name );
    };


    struct QuestionSectionEntry {
        Domainname mDomainname;
        uint16_t   mType;
        uint16_t   mClass;

        QuestionSectionEntry() : mType( 0 ), mClass( 0 )
        {
        }

        uint16_t size() const;
    };

    struct ResourceRecord {
        Domainname mDomainname;
        uint16_t   mType;
        uint16_t   mClass;
        TTL        mTTL;
        RDATAPtr   mRData;

        ResourceRecord() : mType( 0 ), mClass( 0 ), mTTL( 0 )
        {
        }

        uint32_t size() const;

        ResourceRecord( const ResourceRecord &entry )
            : mDomainname( entry.mDomainname ), mType( entry.mType ), mClass( entry.mClass ), mTTL( entry.mTTL )
        {
            if ( entry.mRData )
                mRData = RDATAPtr( entry.mRData->clone() );
        }

        ResourceRecord &operator=( const ResourceRecord &rhs )
        {
            mDomainname = rhs.mDomainname;
            mType       = rhs.mType;
            mClass      = rhs.mClass;
            mTTL        = rhs.mTTL;
            if ( rhs.mRData )
                mRData = RDATAPtr( rhs.mRData->clone() );
            else
                mRData = RDATAPtr();

            return *this;
        }
    };

    struct MessageInfo {
        uint16_t mID;

        uint8_t mQueryResponse;
        uint8_t mOpcode;
        bool    mAuthoritativeAnswer;
        bool    mTruncation;
        bool    mRecursionDesired;

        bool    mRecursionAvailable;
        bool    mCheckingDisabled;
        bool    mZeroField;
        bool    mAuthenticData;
        uint8_t mResponseCode;

        bool mIsEDNS0;
        bool mIsTSIG;

        OptPseudoRecord mOptPseudoRR;
        RecordTSIGData  mTSIGRR;

        std::vector<QuestionSectionEntry> mQuestionSection;
        std::vector<ResourceRecord>       mAnswerSection;
        std::vector<ResourceRecord>       mAuthoritySection;
        std::vector<ResourceRecord>       mAdditionalSection;

        MessageInfo()
            : mID( 0 ), mQueryResponse( 0 ), mOpcode( 0 ), mAuthoritativeAnswer( 0 ), mTruncation( false ),
              mRecursionDesired( false ), mRecursionAvailable( false ), mCheckingDisabled( false ), mZeroField( 0 ),
              mAuthenticData( false ), mResponseCode( 0 ), mIsEDNS0( false ), mIsTSIG( false )
        {
        }

        bool isEDNS0() const
        {
            return mIsEDNS0;
        }

        bool isDNSSECOK() const
        {
            if ( mIsEDNS0 )
                return mOptPseudoRR.mDOBit;
            else
                return false;
        }

        void addOption( std::shared_ptr<OptPseudoRROption> opt );

        const std::vector<QuestionSectionEntry> &getQuestionSection() const
        {
            return mQuestionSection;
        }
        const std::vector<ResourceRecord> &getAnswerSection() const
        {
            return mAnswerSection;
        }
        const std::vector<ResourceRecord> &getAuthoritySection() const
        {
            return mAuthoritySection;
        }
        const std::vector<ResourceRecord> &getAdditionalSection() const
        {
            return mAdditionalSection;
        }

        void pushQuestionSection( const QuestionSectionEntry &e )
        {
            return mQuestionSection.push_back( e );
        }
        void pushAnswerSection( const ResourceRecord &e )
        {
            return mAnswerSection.push_back( e );
        }
        void pushAuthoritySection( const ResourceRecord &e )
        {
            return mAuthoritySection.push_back( e );
        }
        void pushAdditionalSection( const ResourceRecord &e )
        {
            return mAdditionalSection.push_back( e );
        }

        void clearQuestionSection()
        {
            return mQuestionSection.clear();
        }
        void clearAnswerSection()
        {
            return mAnswerSection.clear();
        }
        void clearAuthoritySection()
        {
            return mAuthoritySection.clear();
        }
        void clearAdditionalSection()
        {
            return mAdditionalSection.clear();
        }

        void     generateMessage( WireFormat & ) const;
        uint32_t getMessageSize() const;
    };

    MessageInfo   parseDNSMessage( const uint8_t *begin, const uint8_t *end );
    std::ostream &operator<<( std::ostream &os, const MessageInfo &query );
    std::ostream &printHeader( std::ostream &os, const MessageInfo &packet );
    std::ostream &operator<<( std::ostream &os, const OptPseudoRecord &opt );
    std::string   classCodeToString( Class );
    std::string   typeCodeToString( Type t );
    std::string   responseCodeToString( uint8_t rcode );
    Type          stringToTypeCode( const std::string & );

    struct PacketHeaderField {
        uint16_t id;

        uint8_t recursion_desired : 1;
        uint8_t truncation : 1;
        uint8_t authoritative_answer : 1;
        uint8_t opcode : 4;
        uint8_t query_response : 1;

        uint8_t response_code : 4;
        uint8_t checking_disabled : 1;
        uint8_t authentic_data : 1;
        uint8_t zero_field : 1;
        uint8_t recursion_available : 1;

        uint16_t question_count;
        uint16_t answer_count;
        uint16_t authority_count;
        uint16_t additional_infomation_count;
    };

    ResourceRecord generateOptPseudoRecord( const OptPseudoRecord & );

    void
    addTSIGResourceRecord( const TSIGInfo &tsig_info, WireFormat &message, const PacketData &query_mac = PacketData() );
    bool
    verifyTSIGResourceRecord( const TSIGInfo &tsig_info, const MessageInfo &packet_info, const WireFormat &message );


    template <typename Type>
    Type get_bytes( const uint8_t **pos )
    {
        Type v = *reinterpret_cast<const Type *>( *pos );
        *pos += sizeof( Type );
        return v;
    }
} // namespace dns

#endif
