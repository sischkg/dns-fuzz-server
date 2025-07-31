#include "rrgenerator.hpp"
#include <boost/noncopyable.hpp>
#include <cstdlib>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>

namespace dns
{
    /**********************************************************
     * RandomGenarator
     **********************************************************/
    RandomGenerator *RandomGenerator::mInstance = nullptr;

    RandomGenerator::RandomGenerator() : mGenerator( static_cast<unsigned long>( time( nullptr ) ) )
    {
        std::srand( getpid() * time( nullptr ) );
    }

    uint32_t RandomGenerator::rand( uint32_t base )
    {
        if ( base == 0 )
            return 0;

        boost::mutex::scoped_lock lock( mMutex );
        boost::uniform_smallint<> dst( 0, base );
        uint32_t                  v = dst( mGenerator );
        return v;
    }

    PacketData RandomGenerator::randStream( unsigned int size )
    {
        PacketData stream;
        stream.reserve( size );
        for ( unsigned int i = 0; i < size; i++ )
            stream.push_back( this->rand( 0xff ) );
        return stream;
    }

    PacketData RandomGenerator::randSizeStream( unsigned int max_size )
    {
        unsigned int size = rand( max_size );
        PacketData   stream;
        stream.reserve( size );
        for ( unsigned int i = 0; i < size; i++ )
            stream.push_back( this->rand( 0xff ) );
        return stream;
    }

    RandomGenerator *RandomGenerator::getInstance()
    {
        if ( mInstance == nullptr )
            mInstance = new RandomGenerator();
        return mInstance;
    }

    /**********************************************************
     * DomainnameGenarator
     **********************************************************/
    std::string DomainnameGenerator::generateLabel()
    {
        std::string label;
        if ( getRandom( 37 ) == 0 )
            return "*";

        unsigned int label_size = 1 + getRandom( 62 );
        label.reserve( label_size );
        for ( unsigned int i = 0; i < label_size; i++ )
            label.push_back( getRandom( 0xff ) );
        return label;
    }

    Domainname DomainnameGenerator::generate()
    {
        unsigned int            label_count     = 1 + getRandom( 100 );
        unsigned int            domainname_size = 0;
        std::deque<std::string> labels;
        for ( unsigned int i = 0; i < label_count; i++ ) {
            auto label = generateLabel();
            if ( domainname_size + label.size() + 1 >= 255 )
                break;
            labels.push_back( label );
            domainname_size += ( label.size() + 1 );
        }
        return Domainname( labels );
    }

    Domainname DomainnameGenerator::generate( const Domainname &hint1, const Domainname &hint2 )
    {
        Domainname hint   = hint1;
        Domainname result = hint1;
        if ( hint2 != "" && getRandom( 2 ) == 0 ) {
            hint   = hint2;
            result = hint2;
        }

        switch ( getRandom( 3 ) ) {
        case 0:
            return result;
        case 1: // erase labels;
        {
            unsigned int erased_label_count = getRandom( hint.getLabels().size() );
            for ( unsigned int i = 0; i < erased_label_count; i++ ) {
                result.popSubdomain();
            }

            return result;
        }
        case 2: // append labels as subdomain;
        {
            unsigned int label_count        = hint.getLabels().size();
            unsigned int append_label_count = getRandom( 255 - hint.getLabels().size() );
            unsigned int domainname_size    = hint.size();
            for ( unsigned int i = 0; i < append_label_count; i++ ) {
                std::string new_label = generateLabel();
                if ( label_count + 1 >= 128 || domainname_size + new_label.size() + 1 >= 255 )
                    break;
                result.addSubdomain( new_label );
                domainname_size += ( new_label.size() + 1 );
                label_count++;
            }

            return result;
        }
        case 3: // replace labels;
        {
            unsigned int erased_label_count = getRandom( hint.getLabels().size() );
            for ( unsigned int i = 0; i < erased_label_count; i++ ) {
                result.popSubdomain();
            }

            unsigned int label_count        = result.getLabels().size();
            unsigned int append_label_count = getRandom( 255 - result.getLabels().size() );
            unsigned int domainname_size    = result.size();
            for ( unsigned int i = 0; i < append_label_count; i++ ) {
                std::string new_label = generateLabel();
                if ( label_count + 1 >= 128 || domainname_size + new_label.size() + 1 >= 255 )
                    break;
                result.addSubdomain( new_label );
                domainname_size += ( new_label.size() + 1 );
                label_count++;
            }

            return result;
        }
        default:
            throw std::logic_error( "generate domainname error" );
        }
    }

    static Domainname generateDomainname( const Domainname &hint1, const Domainname &hint2 = Domainname() )
    {
        DomainnameGenerator g;
        return g.generate( hint1, hint2 );
    }

    Domainname generateDomainname()
    {
        DomainnameGenerator g;
        return g.generate();
    }


    Domainname getDomainname( const MessageInfo &hint )
    {
        std::vector<Domainname> names;
        for ( auto rr : hint.getQuestionSection() ) {
            names.push_back( rr.mDomainname );
        }
        for ( auto rr : hint.getAnswerSection() ) {
            names.push_back( rr.mDomainname );
        }
        for ( auto rr : hint.getAuthoritySection() ) {
            names.push_back( rr.mDomainname );
        }
        for ( auto rr : hint.getAdditionalSection() ) {
            names.push_back( rr.mDomainname );
        }

        unsigned int index = getRandom( names.size() - 1 );
        return names.at( index );
    }

    Domainname generateAlgorithmName()
    {
        if ( withChance( 0.7 ) ) {
            const char *algorithms[] = {
                "gss-tsig",
                "HMAC-MD5.SIG-ALG.REG.INT",
                "hmac-sha1",
                "hmac-sha224",
                "hmac-sha256",
                "hmac-sha384",
                "hmac-sha512",
            };

            return (Domainname)algorithms[ getRandom( sizeof( algorithms ) / sizeof( char * ) - 1 ) ];
        } else {
            return generateDomainname();
        }
    }

    /**********************************************************
     * XNAMEGenarator
     **********************************************************/
    template <class T>
    std::shared_ptr<RDATA> XNameGenerator<T>::generate( const MessageInfo &hint, const Domainname &hint2 )
    {
        Domainname hint_name;
        uint32_t   qdcount = hint.getQuestionSection().size();
        uint32_t   ancount = hint.getAnswerSection().size();
        uint32_t   nscount = hint.getAuthoritySection().size();
        uint32_t   adcount = hint.getAdditionalSection().size();

        uint32_t index = getRandom( qdcount + ancount + nscount + adcount - 1 );
        if ( index < qdcount ) {
            hint_name = hint.getQuestionSection().at( index ).mDomainname;
        } else if ( index < qdcount + ancount ) {
            hint_name = hint.getAnswerSection().at( index - qdcount ).mDomainname;
        } else if ( index < qdcount + ancount + nscount ) {
            hint_name = hint.getAuthoritySection().at( index - qdcount - ancount ).mDomainname;
        } else if ( index < qdcount + ancount + nscount + adcount ) {
            hint_name = hint.getAdditionalSection().at( index - qdcount - ancount - nscount ).mDomainname;
        } else {
            throw std::logic_error( "invalid index of XNameGenerator::generate( hint )" );
        }

        return std::shared_ptr<RDATA>( new T( DomainnameGenerator().generate( hint_name, hint2 ) ) );
    }

    template <class T>
    std::shared_ptr<RDATA> XNameGenerator<T>::generate()
    {
        return std::shared_ptr<RDATA>( new T( DomainnameGenerator().generate() ) );
    }


    /**********************************************************
     * RAWGenarator
     **********************************************************/
    std::shared_ptr<RDATA> RawGenerator::generate( const MessageInfo &hint1, const Domainname &hint2 )
    {
        return generate();
    }

    std::shared_ptr<RDATA> RawGenerator::generate()
    {
        return std::shared_ptr<RDATA>( new RecordRaw( getRandom( 0x3ff ), getRandomSizeStream( 0xff ) ) );
    }

    /**********************************************************
     * AGenarator
     **********************************************************/
    std::shared_ptr<RDATA> AGenerator::generate( const MessageInfo &hint, const Domainname &hint2 )
    {
        std::vector<std::shared_ptr<RDATA>> record_a_list;
        for ( auto rr : hint.getAnswerSection() ) {
            if ( rr.mType == TYPE_A ) {
                record_a_list.push_back( rr.mRData );
            }
        }
        for ( auto rr : hint.getAuthoritySection() ) {
            if ( rr.mType == TYPE_A ) {
                record_a_list.push_back( rr.mRData );
            }
        }
        for ( auto rr : hint.getAdditionalSection() ) {
            if ( rr.mType == TYPE_A ) {
                record_a_list.push_back( rr.mRData );
            }
        }

        if ( record_a_list.size() == 0 )
            return generate();

        unsigned int index = getRandom( record_a_list.size() - 1 );
        return std::shared_ptr<RDATA>( record_a_list.at( index )->clone() );
    }

    std::shared_ptr<RDATA> AGenerator::generate()
    {
        return std::shared_ptr<RDATA>( new RecordA( getRandom() ) );
    }


    /**********************************************************
     * WKSGenarator
     **********************************************************/
    std::shared_ptr<RDATA> WKSGenerator::generate( const MessageInfo &hint1, const Domainname &hint2 )
    {
        return generate();
    }

    std::shared_ptr<RDATA> WKSGenerator::generate()
    {
        std::vector<Type> bitmap;
        if ( getRandom( 32 ) == 0 )
            bitmap.resize( 0 );
        else if ( getRandom( 32 ) == 0 ) {
            bitmap.resize( 256 * 256 );
            for ( unsigned int i = 0; i < bitmap.size(); i++ )
                bitmap[ i ] = i;
        } else {
            bitmap.resize( getRandom( 0xffff ) );
            for ( unsigned int i = 0; i < bitmap.size(); i++ )
                bitmap[ i ] = getRandom( 0xffff );
        }

        return std::shared_ptr<RDATA>( new RecordWKS( getRandom(), getRandom( 255 ), bitmap ) );
    }

    /**********************************************************
     * AAAAGenarator
     **********************************************************/
    std::shared_ptr<RDATA> AAAAGenerator::generate( const MessageInfo &hint1, const Domainname &hint2 )
    {
        std::vector<std::shared_ptr<RDATA>> record_a_list;
        for ( auto rr : hint1.getAnswerSection() ) {
            if ( rr.mType == TYPE_AAAA ) {
                record_a_list.push_back( rr.mRData );
            }
        }
        for ( auto rr : hint1.getAuthoritySection() ) {
            if ( rr.mType == TYPE_AAAA ) {
                record_a_list.push_back( rr.mRData );
            }
        }
        for ( auto rr : hint1.getAdditionalSection() ) {
            if ( rr.mType == TYPE_AAAA ) {
                record_a_list.push_back( rr.mRData );
            }
        }

        if ( record_a_list.size() == 0 )
            return generate();

        unsigned int index = getRandom( record_a_list.size() - 1 );
        return std::shared_ptr<RDATA>( record_a_list.at( index )->clone() );
    }

    std::shared_ptr<RDATA> AAAAGenerator::generate()
    {
        PacketData sin_addr = getRandomStream( 16 );
        return std::shared_ptr<RDATA>( new RecordAAAA( &sin_addr[ 0 ] ) );
    }


    /**********************************************************
     * SOAGenarator
     **********************************************************/
    std::shared_ptr<RDATA> SOAGenerator::generate( const MessageInfo &hint1, const Domainname &hint2 )
    {
        return std::shared_ptr<RDATA>( new RecordSOA( getDomainname( hint1 ),
                                                      getDomainname( hint1 ),
                                                      getRandom(),
                                                      getRandom(),
                                                      getRandom(),
                                                      getRandom(),
                                                      getRandom() ) );
    }

    std::shared_ptr<RDATA> SOAGenerator::generate()
    {
        return std::shared_ptr<RDATA>( new RecordSOA( generateDomainname(),
                                                      generateDomainname(),
                                                      getRandom(),
                                                      getRandom(),
                                                      getRandom(),
                                                      getRandom(),
                                                      getRandom() ) );
    }

    /**********************************************************
     * SRVGenarator
     **********************************************************/
    std::shared_ptr<RDATA> SRVGenerator::generate( const MessageInfo &hint1, const Domainname &hint2 )
    {
        return std::shared_ptr<RDATA>(
            new RecordSRV( getRandom( 0xffff ), getRandom( 0xffff ), getRandom( 0xffff ), getDomainname( hint1 ) ) );
    }

    std::shared_ptr<RDATA> SRVGenerator::generate()
    {
        return std::shared_ptr<RDATA>(
            new RecordSRV( getRandom( 0xffff ), getRandom( 0xffff ), getRandom( 0xffff ), generateDomainname() ) );
    }

    /**********************************************************
     * RRSIGGenarator
     **********************************************************/
    std::shared_ptr<RDATA> RRSIGGenerator::generate( const MessageInfo &hint1, const Domainname &hint2 )
    {
        PacketData signature = getRandomSizeStream( 0xff );

        std::shared_ptr<RDATA> p( new RecordRRSIG( getRandom( 0xffff ), // type covered
                                                   getRandom( 0xff ),   // algorithm
                                                   getRandom( 0xff ),   // label
                                                   getRandom(),         // original ttl
                                                   getRandom(),         // expiration
                                                   getRandom(),         // inception
                                                   getRandom( 0xffff ), // key tag
                                                   generateDomainname( getDomainname( hint1 ), hint2 ),
                                                   signature ) );
        return p;
    }

    std::shared_ptr<RDATA> RRSIGGenerator::generate()
    {
        PacketData signature = getRandomSizeStream( 0xff );
        return std::shared_ptr<RDATA>( new RecordRRSIG( getRandom( 0xffff ), // type covered
                                                        getRandom( 0xff ),   // algorithm
                                                        getRandom( 0xff ),   // label
                                                        getRandom(),         // original ttl
                                                        getRandom(),         // expiration
                                                        getRandom(),         // inception
                                                        getRandom( 0xffff ), // key tag
                                                        generateDomainname(),
                                                        signature ) );
    }

    /**********************************************************
     * DNSKEYGenarator
     **********************************************************/
    std::shared_ptr<RDATA> DNSKEYGenerator::generate( const MessageInfo &hint1, const Domainname &hint2 )
    {
        PacketData public_key = getRandomStream( 132 );
        return std::shared_ptr<RDATA>( new RecordDNSKEY(
            getRandom() % 2 ? RecordDNSKEY::KSK : RecordDNSKEY::ZSK, RecordDNSKEY::RSASHA1, public_key ) );
    }

    std::shared_ptr<RDATA> DNSKEYGenerator::generate()
    {
        PacketData public_key = getRandomStream( 132 );
        return std::shared_ptr<RDATA>( new RecordDNSKEY(
            getRandom() % 2 ? RecordDNSKEY::KSK : RecordDNSKEY::ZSK, RecordDNSKEY::RSASHA1, public_key ) );
    }


    /**********************************************************
     * DSGenarator
     **********************************************************/
    std::shared_ptr<RDATA> DSGenerator::generate( const MessageInfo &hint1, const Domainname &hint2 )
    {
        if ( getRandom( 2 ) ) {
            PacketData hash = getRandomStream( 20 );
            return std::shared_ptr<RDATA>( new RecordDS( getRandom( 0xffff ), 5, 1, hash ) );
        } else {
            PacketData hash = getRandomStream( 32 );
            return std::shared_ptr<RDATA>( new RecordDS( getRandom( 0xffff ), 5, 2, hash ) );
        }
    }

    std::shared_ptr<RDATA> DSGenerator::generate()
    {
        if ( getRandom( 2 ) ) {
            PacketData hash = getRandomStream( 40 );
            return std::shared_ptr<RDATA>( new RecordDS( getRandom( 0xffff ), 5, 1, hash ) );
        } else {
            PacketData hash = getRandomStream( 64 );
            return std::shared_ptr<RDATA>( new RecordDS( getRandom( 0xffff ), 5, 2, hash ) );
        }
    }


    /**********************************************************
     * NSECGenarator
     **********************************************************/
    std::shared_ptr<RDATA> NSECGenerator::generate( const MessageInfo &hint1, const Domainname &hint2 )
    {
        std::vector<Type> types;
        unsigned int      type_count = getRandom( 4 );
        types.reserve( type_count );
        for ( unsigned int i = 0; i < type_count; i++ ) {
            types.push_back( getRandom( 0xffff ) );
        }

        return std::shared_ptr<RDATA>( new RecordNSEC( generateDomainname( getDomainname( hint1 ), hint2 ), types ) );
    }

    std::shared_ptr<RDATA> NSECGenerator::generate()
    {
        std::vector<Type> types;
        unsigned int      type_count = getRandom( 0xffff );
        types.reserve( type_count );
        for ( unsigned int i = 0; i < type_count; i++ ) {
            types.push_back( getRandom( 0xffff ) );
        }

        return std::shared_ptr<RDATA>( new RecordNSEC( generateDomainname(), types ) );
    }

    /**********************************************************
     * NSEC3Genarator
     **********************************************************/
    std::shared_ptr<RDATA> NSEC3Generator::generate( const MessageInfo &hint1, const Domainname &hint2 )
    {
        return generate();
    }

    std::shared_ptr<RDATA> NSEC3Generator::generate()
    {
        uint8_t optout = 0x07;
        if ( getRandom( 8 ) ) {
            optout = 0;
        }
        std::vector<Type> types;
        unsigned int      type_count = getRandom( 4 );
        for ( unsigned int i = 0; i < type_count; i++ ) {
            types.push_back( getRandom( 0xffff ) );
        }

        return std::shared_ptr<RDATA>( new RecordNSEC3(
            0x01, optout, getRandom( 0x00ff ), getRandomSizeStream( 0xff ), getRandomStream( 20 ), types ) );
    }


    /**********************************************************
     * NSEC3PARAMGenarator
     **********************************************************/
    std::shared_ptr<RDATA> NSEC3PARAMGenerator::generate( const MessageInfo &hint1, const Domainname &hint2 )
    {
        return generate();
    }

    std::shared_ptr<RDATA> NSEC3PARAMGenerator::generate()
    {
        uint8_t optout = 0x07;
        if ( getRandom( 8 ) ) {
            optout = 0;
        }

        return std::shared_ptr<RDATA>(
            new RecordNSEC3PARAM( 0x01, optout, getRandom( 0x00ff ), getRandomSizeStream( 0xff ) ) );
    }

    /**********************************************************
     * TLSAGenarator
     **********************************************************/
    std::shared_ptr<RDATA> TLSAGenerator::generate( const MessageInfo &hint1, const Domainname &hint2 )
    {
        return generate();
    }

    std::shared_ptr<RDATA> TLSAGenerator::generate()
    {
        return std::shared_ptr<RDATA>(
            new RecordTLSA( getRandom( 0xff ), getRandom( 0xff ), getRandom( 0xff ), getRandomSizeStream( 0x01ff ) ) );
    }

    /**********************************************************
     * SIGGenarator
     **********************************************************/
    std::shared_ptr<RDATA> SIGGenerator::generate( const MessageInfo &hint1, const Domainname &hint2 )
    {
        PacketData signature = getRandomStream( 256 );

        std::shared_ptr<RDATA> p( new RecordSIG( getRandom( 0xffff ), // type covered
                                                 getRandom( 0xff ),   // algorithm
                                                 getRandom( 0xff ),   // label
                                                 getRandom(),         // original ttl
                                                 getRandom(),         // expiration
                                                 getRandom(),         // inception
                                                 getRandom( 0xffff ), // key tag
                                                 generateDomainname( getDomainname( hint1 ), hint2 ),
                                                 signature ) );
        return p;
    }

    std::shared_ptr<RDATA> SIGGenerator::generate()
    {
        PacketData signature = getRandomSizeStream( 256 );
        return std::shared_ptr<RDATA>( new RecordSIG( getRandom( 0xffff ), // type covered
                                                      getRandom( 0xff ),   // algorithm
                                                      getRandom( 0xff ),   // label
                                                      getRandom(),         // original ttl
                                                      getRandom(),         // expiration
                                                      getRandom(),         // inception
                                                      getRandom( 0xffff ), // key tag
                                                      generateDomainname(),
                                                      signature ) );
    }

    /**********************************************************
     * KEYGenarator
     **********************************************************/
    std::shared_ptr<RDATA> KEYGenerator::generate( const MessageInfo &hint1, const Domainname &hint2 )
    {
        PacketData public_key = getRandomStream( 132 );
        return std::shared_ptr<RDATA>( new RecordKEY( 0xffff, RecordDNSKEY::RSASHA1, public_key ) );
    }

    std::shared_ptr<RDATA> KEYGenerator::generate()
    {
        PacketData public_key = getRandomStream( 132 );
        return std::shared_ptr<RDATA>( new RecordKEY( getRandom( 0xffff ), RecordDNSKEY::RSASHA1, public_key ) );
    }

    /**********************************************************
     * NXTGenarator
     **********************************************************/
    std::shared_ptr<RDATA> NXTGenerator::generate( const MessageInfo &hint1, const Domainname &hint2 )
    {
        std::vector<Type> types;
        unsigned int      type_count = getRandom( 0xffff );
        types.reserve( type_count );
        for ( unsigned int i = 0; i < type_count; i++ ) {
            types.push_back( getRandom( 0xffff ) );
        }

        return std::shared_ptr<RDATA>( new RecordNXT( generateDomainname( getDomainname( hint1 ), hint2 ), types ) );
    }

    std::shared_ptr<RDATA> NXTGenerator::generate()
    {
        std::vector<Type> types;
        unsigned int      type_count = getRandom( 0xffff );
        types.reserve( type_count );
        for ( unsigned int i = 0; i < type_count; i++ ) {
            types.push_back( getRandom( 0xffff ) );
        }

        return std::shared_ptr<RDATA>( new RecordNXT( generateDomainname(), types ) );
    }

    /**********************************************************
     * TKEYGenarator
     **********************************************************/
    std::shared_ptr<RDATA> TKEYGenerator::generate( const MessageInfo &hint1, const Domainname &hint2 )
    {
        PacketData signature = getRandomSizeStream( 0xff );
        PacketData other     = getRandomSizeStream( 0xff );

        std::shared_ptr<RDATA> p( new RecordTKEY( generateDomainname( getDomainname( hint1 ), hint2 ), // domain
                                                  generateAlgorithmName(),                             // algorithm
                                                  getRandom(),                                         // inception
                                                  getRandom(),                                         // expiration
                                                  getRandom( 0xff ),
                                                  getRandom( 0xff ),
                                                  signature,
                                                  other ) );
        return p;
    }

    std::shared_ptr<RDATA> TKEYGenerator::generate()
    {
        PacketData signature = getRandomSizeStream( 0xff );
        PacketData other     = getRandomSizeStream( 0xff );

        std::shared_ptr<RDATA> p( new RecordTKEY( generateDomainname(),    // domain
                                                  generateAlgorithmName(), // algorithm
                                                  getRandom(),             // inception
                                                  getRandom(),             // expiration
                                                  getRandom(),
                                                  getRandom(),
                                                  signature ) );
        return p;
    }

    /**********************************************************
     * TSIGGenarator
     **********************************************************/
    std::shared_ptr<RDATA> TSIGGenerator::generate( const MessageInfo &hint1, const Domainname &hint2 )
    {
        PacketData signature   = getRandomStream( 16 );
        uint64_t   signed_time = (uint64_t)getRandom() + ( ( (uint64_t)getRandom() ) << 32 );

        PacketData other = getRandomSizeStream( 0xff );

        return std::shared_ptr<RDATA>(
            new RecordTSIGData( generateDomainname( getDomainname( hint1 ), hint2 ), // domain
                                generateAlgorithmName(),                             // algorithm
                                signed_time,                                         // signed time
                                getRandom( 0xffff ),                                 // fudge
                                signature,                                           // mac
                                getRandom( 0xffff ),                                 // original id
                                getRandom( 0xffff ),                                 // error
                                other ) );
    }

    std::shared_ptr<RDATA> TSIGGenerator::generate()
    {
        PacketData signature   = getRandomStream( 16 );
        uint64_t   signed_time = (uint64_t)getRandom() + ( ( (uint64_t)getRandom() ) << 32 );

        PacketData other = getRandomSizeStream( 0xff );

        return std::shared_ptr<RDATA>( new RecordTSIGData( generateDomainname(),    // domain
                                                           generateAlgorithmName(), // algorithm
                                                           signed_time,             // signed time
                                                           getRandom( 0xffff ),     // fudge
                                                           signature,               // mac
                                                           getRandom( 0xffff ),     // original id
                                                           getRandom( 0xffff ),     // error
                                                           other ) );
    }


    /**********************************************************
     * ResourceRecordGenarator
     **********************************************************/
    ResourceRecordGenerator::ResourceRecordGenerator()
    {
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new RawGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new NSGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new CNAMEGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new DNAMEGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new AGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new AAAAGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new WKSGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new SOAGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new SRVGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new RRSIGGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new DNSKEYGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new DSGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new NSECGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new NSEC3Generator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new NSEC3PARAMGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new TLSAGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new SIGGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new KEYGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new NXTGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new TKEYGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new TSIGGenerator ) );
    }


    RRSet ResourceRecordGenerator::generate( const MessageInfo &hint1, const Domainname &hint2 )
    {
        Class class_table[] = { CLASS_IN, CLASS_CH, CLASS_HS, CLASS_NONE, CLASS_ANY };

        std::shared_ptr<RDATA> resource_data =
            mGenerators.at( getRandom( mGenerators.size() - 1 ) )->generate( hint1, hint2 );

        Domainname owner;
        if ( resource_data->type() == TYPE_NSEC3 ) {
            std::string hash;
            encodeToBase32Hex( getRandomStream( 20 ), hash );
            owner = getDomainname( hint1 );
            owner.addSubdomain( hash );
        } else {
            owner = generateDomainname( getDomainname( hint1 ), hint2 );
        }

        unsigned int index = getRandom( sizeof( class_table ) / sizeof( Class ) - 1 );
        if ( index >= sizeof( class_table ) / sizeof( Class ) ) {
            throw std::logic_error( "invalid class index" );
        }
        RRSet rrset( owner, class_table[ index ], resource_data->type(), getRandom( 0xffffffff ) );
        rrset.add( resource_data );

        return rrset;
    }

    std::shared_ptr<OptPseudoRROption> RawOptionGenerator::generate( const MessageInfo &hint )
    {
        return generate();
    }

    std::shared_ptr<OptPseudoRROption> RawOptionGenerator::generate()
    {
        return std::shared_ptr<OptPseudoRROption>( new RAWOption( getRandom( 0x0f ), getRandomSizeStream( 0xff ) ) );
    }

    std::shared_ptr<OptPseudoRROption> NSIDGenerator::generate( const MessageInfo &hint )
    {
        return generate();
    }

    std::shared_ptr<OptPseudoRROption> NSIDGenerator::generate()
    {
        ssize_t     length = getRandom( 0xff );
        std::string data;
        data.reserve( length );
        for ( ssize_t i = 0; i < length; i++ )
            data.push_back( getRandom( 0xff ) );
        return std::shared_ptr<OptPseudoRROption>( new NSIDOption( data ) );
    }

    std::shared_ptr<OptPseudoRROption> ClientSubnetGenerator::generate( const MessageInfo &hint )
    {
        return generate();
    }

    std::shared_ptr<OptPseudoRROption> ClientSubnetGenerator::generate()
    {
        if ( getRandom( 2 ) ) {
            std::ostringstream os;
            os << getRandom( 0xff ) << "." << getRandom( 0xff ) << "." << getRandom( 0xff ) << getRandom( 0xff );
            return std::shared_ptr<OptPseudoRROption>(
                new ClientSubnetOption( ClientSubnetOption::IPv4, getRandom( 32 ), getRandom( 32 ), os.str() ) );
        } else {
            std::ostringstream os;
            os << std::hex << getRandom( 0xff );
            for ( int i = 0; i < 15; i++ )
                os << ":" << getRandom( 0xff );
            return std::shared_ptr<OptPseudoRROption>(
                new ClientSubnetOption( ClientSubnetOption::IPv6, getRandom( 128 ), getRandom( 128 ), os.str() ) );
        }
    }


    std::shared_ptr<OptPseudoRROption> CookieGenerator::generate( const MessageInfo &hint )
    {
        return generate();
    }

    std::shared_ptr<OptPseudoRROption> CookieGenerator::generate()
    {
        PacketData   client, server;
        unsigned int client_length = getRandom( 64 );
        unsigned int server_length = getRandom( 64 );

        client.reserve( client_length );
        server.reserve( server_length );
        for ( unsigned int i = 0; i < client_length; i++ )
            client.push_back( getRandom( 0xff ) );
        for ( unsigned int i = 0; i < server_length; i++ )
            server.push_back( getRandom( 0xff ) );

        return std::shared_ptr<OptPseudoRROption>( new CookieOption( client, server ) );
    }


    std::shared_ptr<OptPseudoRROption> TCPKeepaliveGenerator::generate( const MessageInfo &hint )
    {
        return generate();
    }

    std::shared_ptr<OptPseudoRROption> TCPKeepaliveGenerator::generate()
    {
        uint16_t timeout = 0;
        if ( getRandom( 4 ) ) {
            timeout = getRandom( 0xffff );
        }
        return std::shared_ptr<OptPseudoRROption>( new TCPKeepaliveOption( timeout ) );
    }


    std::shared_ptr<OptPseudoRROption> KeyTagGenerator::generate( const MessageInfo &hint )
    {
        return generate();
    }

    std::shared_ptr<OptPseudoRROption> KeyTagGenerator::generate()
    {
        uint16_t              count = getRandom( 0x0fff );
        std::vector<uint16_t> tags;
        tags.reserve( count );
        for ( uint16_t i = 0; i < count; i++ )
            tags.push_back( getRandom( 0xffff ) );
        return std::shared_ptr<OptPseudoRROption>( new KeyTagOption( tags ) );
    }

    std::shared_ptr<OptPseudoRROption> ExtendedErrorGenerator::generate( const MessageInfo &hint )
    {
        return generate();
    }

    std::shared_ptr<OptPseudoRROption> ExtendedErrorGenerator::generate()
    {
        uint16_t    text_size = getRandom( 0xffff );
        std::string text;
        for ( uint32_t i = 0; i < text_size; i++ ) {
            text.push_back( (uint8_t)getRandom( 0xff ) );
        }
        return std::shared_ptr<OptPseudoRROption>( new ExtendedErrorOption( (uint16_t)getRandom( 0xffff ), text ) );
    }

    /**********************************************************
     * OptionGenarator
     **********************************************************/
    OptionGenerator::OptionGenerator()
    {
        mGenerators.push_back( std::shared_ptr<OptGeneratable>( new RawOptionGenerator ) );
        mGenerators.push_back( std::shared_ptr<OptGeneratable>( new NSIDGenerator ) );
        mGenerators.push_back( std::shared_ptr<OptGeneratable>( new ClientSubnetGenerator ) );
        mGenerators.push_back( std::shared_ptr<OptGeneratable>( new CookieGenerator ) );
        mGenerators.push_back( std::shared_ptr<OptGeneratable>( new TCPKeepaliveGenerator ) );
        mGenerators.push_back( std::shared_ptr<OptGeneratable>( new KeyTagGenerator ) );
        mGenerators.push_back( std::shared_ptr<OptGeneratable>( new ExtendedErrorGenerator ) );
    }


    void OptionGenerator::generate( MessageInfo &packet )
    {
        if ( !packet.isEDNS0() )
            return;

        std::shared_ptr<OptPseudoRROption> option =
            mGenerators.at( getRandom( mGenerators.size() - 1 ) )->generate( packet );
        packet.addOption( option );
    }
} // namespace dns
