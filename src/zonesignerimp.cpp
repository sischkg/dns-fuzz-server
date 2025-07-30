#include "zonesignerimp.hpp"
#include <string>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <iterator>
#include <openssl/rsa.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>

namespace dns
{
    SignAlgorithm stringToSignAlgorithm( const std::string &str )
    {
	if ( str == "RSASHA1" )
	    return DNSSEC_RSASHA1;
	else if ( str == "RSASHA256" )
	    return DNSSEC_RSASHA256;
	else if ( str == "ECDSAP256SHA256" )
	    return DNSSEC_ECDSAP256SHA256;
	else if ( str == "ECDSAP256SHA384" )
	    return DNSSEC_ECDSAP384SHA384;

	throw std::runtime_error( "unknown algorithm \"" + str + "\"" );
    }

    const EVP_MD *enumToSignMD( SignAlgorithm algo )
    {
        switch ( algo ) {
        case DNSSEC_RSASHA1:
            return EVP_sha1();
        case DNSSEC_RSASHA256:
            return EVP_sha256();
        case DNSSEC_ECDSAP256SHA256:
            return EVP_sha256();
        case DNSSEC_ECDSAP384SHA384:
            return EVP_sha384();
        default:
            throw std::runtime_error( "unknown hash algorighm for RRSIG" );
        }
    }

    const EVP_MD *enumToDigestMD( HashAlgorithm algo )
    {
        switch ( algo ) {
        case DNSSEC_SHA1:
            return EVP_sha1();
        case DNSSEC_SHA256:
            return EVP_sha256();
        case DNSSEC_SHA384:
            return EVP_sha384();
        default:
            throw std::runtime_error( "unknown hash algorighm for DS" );
        }
    }

    static uint8_t getLabelCountOfCanonicalDomainname( const Domainname &name )
    {
        unsigned int label_count = name.getLabels().size();
        // check wildcard
        if ( label_count != 0 ) {
            std::string label = name.getLabels()[0];
            if ( label == "*" ) {
                label_count--;
            }
        }
        return label_count;
    }

    void throwException( const char *message, const char *other )
    {
        unsigned int code = ERR_get_error();
        char openssl_error[1024];
        std::memset( openssl_error, 0, sizeof(openssl_error) );
        ERR_error_string_n( code, openssl_error, sizeof(openssl_error) );
 
        std::ostringstream err;
        err << message;
        if ( other != nullptr )
            err << "\"" << other << "\"";
        err << "(" << openssl_error << ")";

        std::runtime_error( err.str() );
    }

    void throwException( const std::string &message, const char *other )
    {
	throwException( message.c_str(), other );
    }

    /*******************************************************************************************
     * PrivateKeyImp
     *******************************************************************************************/
    PrivateKeyImp::~PrivateKeyImp()
    {
        EVP_PKEY_free( mPrivateKey );
    }

    EVP_PKEY *PrivateKeyImp::loadPrivateKey( const std::string &key_filename )
    {
        // Load Private / Public Key
        FILE *fp_private_key = std::fopen( key_filename.c_str(), "r" );
        if ( ! fp_private_key ) {
            throw std::runtime_error( "cannot open private key \"" + key_filename + "\"" );
        }
        BIO *bio_private_key = BIO_new_fp( fp_private_key, BIO_CLOSE );
        if ( ! bio_private_key ) {
            throw std::runtime_error( "cannot create bio for private key file" );
        }

        EVP_PKEY *private_key = PEM_read_bio_PrivateKey( bio_private_key, NULL, NULL, NULL );
        if ( ! private_key ) {
            throw std::runtime_error( "cannot read private key" );
        }
        BIO_free_all( bio_private_key );

	return private_key;
    }

    std::vector<std::shared_ptr<PrivateKeyImp>> PrivateKeyImp::loadConfig( const std::string &config_filename )
    {
        std::ifstream fs( config_filename );
        std::istreambuf_iterator<char> begin( fs );
        std::istreambuf_iterator<char> end;

        if ( !fs ) {
            throw std::runtime_error( "cannot load config file \"" + config_filename + "\"" );
        }
        std::string config( begin, end );
        return load( config );
    }


    std::vector<std::shared_ptr<PrivateKeyImp>> PrivateKeyImp::load( const std::string &config )
    {
        YAML::Node top;
        try {
            top = YAML::Load( config );
        }
        catch( YAML::ParserException &e ) {
            throw std::runtime_error( "cannot load private key " + config + ": " + e.what() );
        }

	std::vector<std::shared_ptr<PrivateKeyImp>> keys;
	for ( auto key_config = top.begin() ; key_config != top.end() ; key_config++ ) {
	
	    KeyType        key_type    = ZSK;
	    SignAlgorithm  sign_algo   = DNSSEC_RSASHA1;
	    EVP_PKEY      *private_key = nullptr;
	    uint32_t       not_before  = 0;
	    uint32_t       not_after   = 0;
	    Domainname     domain;

	    std::string key_type_name = loadParameter<std::string>( *key_config, "type" );
	    if ( key_type_name == "ksk" )
		key_type = KSK;
   
	    private_key = loadPrivateKey( loadParameter<std::string>( *key_config, "key_file" ) );

	    sign_algo  = stringToSignAlgorithm( loadParameter<std::string>( *key_config, "algorithm" ) );
	    not_before = loadParameter<uint32_t>( *key_config, "not_before" );
	    not_after  = loadParameter<uint32_t>( *key_config, "not_after" );
	    domain     = Domainname( loadParameter<std::string>( *key_config, "domain" ) );

            switch ( sign_algo ) {
            case DNSSEC_RSASHA1:
                keys.push_back( std::shared_ptr<PrivateKeyImp>( new RSAPrivateKeyImp( key_type,
                                                                                      private_key,
                                                                                      not_before,
                                                                                      not_after,
                                                                                      domain,
                                                                                      NID_sha1 ) ) );
                break;
            case DNSSEC_RSASHA256:
                keys.push_back( std::shared_ptr<PrivateKeyImp>( new RSAPrivateKeyImp( key_type,
                                                                                      private_key,
                                                                                      not_before,
                                                                                      not_after,
                                                                                      domain,
                                                                                      NID_sha1 ) ) );
                break;
            case DNSSEC_ECDSAP256SHA256:
                keys.push_back( std::shared_ptr<PrivateKeyImp>( new ECDSAP256SHA256PrivateKeyImp( key_type,
                                                                                                  private_key,
                                                                                                  not_before,
                                                                                                  not_after,
                                                                                                  domain ) ) );
                break;
            case DNSSEC_ECDSAP384SHA384:
                keys.push_back( std::shared_ptr<PrivateKeyImp>( new ECDSAP384SHA384PrivateKeyImp( key_type,
                                                                                                  private_key,
                                                                                                  not_before,
                                                                                                  not_after,
                                                                                                  domain ) ) );
                break;
            }
	}
        return keys;
    }

    std::shared_ptr<RecordDNSKEY> PrivateKeyImp::getDNSKEYRecord() const
    {
        std::shared_ptr<PublicKey> public_key = getPublicKey();

        return std::shared_ptr<RecordDNSKEY>( new RecordDNSKEY( getKeyType(),
                                                                getAlgorithm(),
                                                                public_key->getDNSKEYFormat() ) );
    }


    uint16_t PrivateKeyImp::getKeyTag() const
    {
        std::shared_ptr<RecordDNSKEY> dnskey = getDNSKEYRecord();
        WireFormat message;
        dnskey->outputCanonicalWireFormat( message );

        // From RFC4034
        uint32_t ac = 0;

        for ( int i = 0; i < message.size() ; ++i )
            ac += (i & 1) ? message[i] : message[i] << 8;
        ac += (ac >> 16) & 0xFFFF;
        return ac & 0xffff;
    }


    /*******************************************************************************************
     * RSAPrivateKeyImp
     *******************************************************************************************/
    std::shared_ptr<PublicKey> RSAPrivateKeyImp::getPublicKey() const
    {
	const RSA* r = EVP_PKEY_get0_RSA( getPrivateKey() );
	const BIGNUM *modulus, *public_exponent, *private_exponent;

	RSA_get0_key( r, &modulus, &public_exponent, &private_exponent );
	PacketData public_exponent_buf( BN_num_bytes( public_exponent ) );
	PacketData modulus_buf( BN_num_bytes( modulus ) );

	BN_bn2bin( public_exponent, &public_exponent_buf[0] );
	BN_bn2bin( modulus,         &modulus_buf[0] );

	return std::shared_ptr<RSAPublicKey>( new RSAPublicKey( public_exponent_buf, modulus_buf ) );
    }

    void RSAPrivateKeyImp::sign( EVP_MD_CTX *md_ctx, const WireFormat &message, PacketData &signature ) const
    {
	unsigned int digest_length = EVP_MAX_MD_SIZE;
	const EVP_MD *sign_algo = enumToSignMD( getAlgorithm() );

	EVP_DigestInit_ex( md_ctx, sign_algo, NULL);

	PacketData digest_target = message.get();
	int res = EVP_DigestUpdate( md_ctx, &digest_target[0], digest_target.size() );
        if ( 0 == res )
            throwException( "EVP_DigestUpdata failed" );
	PacketData digest( EVP_MAX_MD_SIZE );
	res = EVP_DigestFinal_ex( md_ctx, &digest[0], &digest_length );
        if ( 0 == res )
            throwException( "EVP_DigestFinal failed" );
	digest.resize( digest_length );

	const RSA* rsa = EVP_PKEY_get0_RSA( getPrivateKey() );
	unsigned int signature_length = RSA_size( rsa );
	signature.resize( signature_length );
	int result = RSA_sign( mHashAlgorithm, &digest[0], digest_length, &signature[0], &signature_length, const_cast<RSA *>( rsa ) );

	if ( result != 1 ) {
	    throwException( "RSA_sign failed" );
	}
	signature.resize( signature_length );
    }

    /*******************************************************************************************
     * ECDSAPrivateKeyImp
     *******************************************************************************************/
    template <uint8_t SIGN_ALGO>
    std::shared_ptr<PublicKey> ECDSAPrivateKeyImp<SIGN_ALGO>::getPublicKey() const
    {
	EC_KEY* ec = EVP_PKEY_get1_EC_KEY( getPrivateKey() );
	unsigned int public_key_size = i2o_ECPublicKey( ec, nullptr );
	PacketData buf( public_key_size );
	uint8_t *p = &buf[0];
	if ( ! i2o_ECPublicKey( ec, &p ) )
	    throw std::runtime_error( "cannot get public key from private key" );
	return std::shared_ptr<ECDSAPublicKey>( new ECDSAPublicKey( &buf[1], buf.size() - 1 ) );
    }
    
    template <uint8_t SIGN_ALGO>
    void ECDSAPrivateKeyImp<SIGN_ALGO>::sign( EVP_MD_CTX *md_ctx, const WireFormat &message, PacketData &signature ) const
    {
	unsigned int digest_length = EVP_MAX_MD_SIZE;
	const EVP_MD *sign_algo = enumToSignMD( getAlgorithm() );

	EVP_DigestInit_ex( md_ctx, sign_algo, NULL);

	PacketData digest_target = message.get();
	int res = EVP_DigestUpdate( md_ctx, &digest_target[0], digest_target.size() );
        if ( res != 1 ) {
	    throwException( "EVP_DigestUpdate failed" );
        }
	PacketData digest( EVP_MAX_MD_SIZE );
	EVP_DigestFinal_ex( md_ctx, &digest[0], &digest_length );
	digest.resize( digest_length );

	EC_KEY *ec = EVP_PKEY_get1_EC_KEY( getPrivateKey() );
        ECDSA_SIG *ecdsa_sig = ECDSA_do_sign( &digest[0], digest_length, ec );
	if ( ecdsa_sig == nullptr ) {
	    throwException( "ECDSA_sign failed" );
	}

        const BIGNUM *r, *s;
        ECDSA_SIG_get0( ecdsa_sig, &r, &s );
        PacketData r_buf( BN_num_bytes(r) );
        PacketData s_buf( BN_num_bytes(s) );

        BN_bn2bin( r, &r_buf[0] );
        BN_bn2bin( s, &s_buf[0] );
        signature.clear();
	signature.insert( signature.end(), r_buf.begin(), r_buf.end() );
	signature.insert( signature.end(), s_buf.begin(), s_buf.end() );
        ECDSA_SIG_free( ecdsa_sig );
    }

    /*******************************************************************************************
     * ZoneSingerImp
     *******************************************************************************************/

    ZoneSignerImp::ZoneSignerImp( const Domainname &apex,
				  const std::string &ksk_filename,
				  const std::string &zsk_filename )
        : mApex( apex ), mMDContext( nullptr )
    {
	try {
	    mKSKs = PrivateKeyImp::loadConfig( ksk_filename );
	    mZSKs = PrivateKeyImp::loadConfig( zsk_filename );

	    mMDContext = EVP_MD_CTX_new();
	    if ( ! mMDContext ) {
		throwException( "cannot create MD_CTX" );
	    }
	}
	catch ( std::runtime_error &e ) {
	    if ( mMDContext != nullptr )
		EVP_MD_CTX_destroy( mMDContext );
	    throw;
	}	
    }

    ZoneSignerImp::~ZoneSignerImp()
    {
        EVP_MD_CTX_destroy( mMDContext );
    }

    void ZoneSignerImp::sign( const WireFormat &message,
			      PacketData &signature,
			      const PrivateKeyImp &key ) const
    {
        key.sign( mMDContext, message, signature );
    }

    void ZoneSignerImp::generateSignData( const RRSet &rrset, const PrivateKeyImp &key, WireFormat &sign_target ) const
    {
	sign_target.clear();
 
	sign_target.pushUInt16HtoN( rrset.getType() );                 // type covered
	sign_target.pushUInt8( key.getAlgorithm() );                   // algorithm
	sign_target.pushUInt8( getLabelCountOfCanonicalDomainname( rrset.getOwner() ) );  // label count
	sign_target.pushUInt32HtoN( rrset.getTTL() );                  // original ttl
	sign_target.pushUInt32HtoN( key.getNotAfter() );               // expiration
	sign_target.pushUInt32HtoN( key.getNotBefore() );              // inception
	sign_target.pushUInt16HtoN( key.getKeyTag() );                // key tag
	key.getDomainname().outputCanonicalWireFormat( sign_target );  // signer 
	
	std::vector<RDATAPtr> ordered_rrs = rrset.getRRSet();
	std::sort( ordered_rrs.begin(),
		   ordered_rrs.end(),
		   []( const RDATAPtr &lhs, const RDATAPtr &rhs )
		   {
		       WireFormat lhs_data, rhs_data;
		       lhs->outputCanonicalWireFormat( lhs_data );
		       rhs->outputCanonicalWireFormat( rhs_data );
		       return lhs_data < rhs_data;
		   } );

	for ( auto rr : ordered_rrs ) {
	    rrset.getOwner().outputCanonicalWireFormat( sign_target );
	    sign_target.pushUInt16HtoN( rrset.getType() );
	    sign_target.pushUInt16HtoN( rrset.getClass() );
	    sign_target.pushUInt32HtoN( rrset.getTTL() );
	    WireFormat tmp;
	    rr->outputCanonicalWireFormat( tmp );
	    sign_target.pushUInt16HtoN( tmp.size() );
	    sign_target.pushBuffer( tmp.get() );
	}
    }

    std::shared_ptr<RecordRRSIG> ZoneSignerImp::generateRRSIG( const RRSet &rrset, const PrivateKeyImp &key ) const
    {
	WireFormat sign_target;
	generateSignData( rrset, key, sign_target );
	PacketData signature;
	sign( sign_target, signature, key );

        return std::shared_ptr<RecordRRSIG>( new RecordRRSIG( rrset.getType(),
                                                              key.getAlgorithm(),
                                                              getLabelCountOfCanonicalDomainname( rrset.getOwner() ),
                                                              rrset.getTTL(),
                                                              key.getNotAfter(),
                                                              key.getNotBefore(),
                                                              key.getKeyTag(),
                                                              key.getDomainname(),
                                                              signature ) );
    }

    std::shared_ptr<RRSet> ZoneSignerImp::signRRSetByKeys( const RRSet &rrset, const std::vector<std::shared_ptr<PrivateKeyImp> > &keys ) const
    {
        std::shared_ptr<RRSet> rrsig_rrset( new RRSet( rrset.getOwner(),
                                                       rrset.getClass(),
                                                       TYPE_RRSIG,
                                                       rrset.getTTL() ) );
        for ( auto key : keys ) {
            rrsig_rrset->add( generateRRSIG( rrset, *key ) );
        }

	return rrsig_rrset;
    }


    std::shared_ptr<RRSet> ZoneSignerImp::signRRSet( const RRSet &rrset ) const
    {
	return signRRSetByKeys( rrset, mZSKs );
    }

    std::shared_ptr<RRSet> ZoneSignerImp::signDNSKEY( TTL ttl ) const
    {
	std::vector<std::shared_ptr<RecordDNSKEY>> dnskeys = getDNSKEYRecords();
	RRSet rrset( mApex, CLASS_IN, TYPE_DNSKEY, ttl );
	for ( auto k : dnskeys )
	    rrset.add( k );

        std::vector<std::shared_ptr<PrivateKeyImp> > keys;
        keys.insert( keys.end(), mKSKs.begin(), mKSKs.end() );
        keys.insert( keys.end(), mZSKs.begin(), mZSKs.end() );

	return signRRSetByKeys( rrset, keys );
    }


    std::vector<std::shared_ptr<RecordDNSKEY>> ZoneSignerImp::getDNSKEYRecords() const
    {
        std::vector<std::shared_ptr<RecordDNSKEY>> result;
	for ( auto ksk : mKSKs )
	    result.push_back( ksk->getDNSKEYRecord() );
	for ( auto zsk : mZSKs )
	    result.push_back( zsk->getDNSKEYRecord() );
        return result;
    }

    std::shared_ptr<RecordDS> ZoneSignerImp::getDSRecord( const PrivateKeyImp &ksk, HashAlgorithm algo ) const
    {
        WireFormat hash_target;
        ksk.getDomainname().outputCanonicalWireFormat( hash_target );
        std::shared_ptr<RecordDNSKEY> dnskey = ksk.getDNSKEYRecord();
        dnskey->outputCanonicalWireFormat( hash_target );
        PacketData hash_target_data = hash_target.get();

        unsigned int digest_length = EVP_MAX_MD_SIZE;
        EVP_DigestInit_ex( mMDContext, enumToDigestMD( algo ), NULL);
        EVP_DigestUpdate( mMDContext, &hash_target_data[0], hash_target_data.size() );
        PacketData digest( EVP_MAX_MD_SIZE );
        EVP_DigestFinal_ex( mMDContext, &digest[0], &digest_length );
        digest.resize( digest_length );

        return std::shared_ptr<RecordDS>( new RecordDS( ksk.getKeyTag(),
                                                        ksk.getAlgorithm(),
                                                        algo,
                                                        digest ) );
    }

    std::vector<std::shared_ptr<RecordDS>> ZoneSignerImp::getDSRecords() const
    {
        std::vector<std::shared_ptr<RecordDS>> result;
	for ( auto ksk : mKSKs ) {
	    result.push_back( getDSRecord( *ksk, DNSSEC_SHA1 ) );
	    result.push_back( getDSRecord( *ksk, DNSSEC_SHA256 ) );
	    result.push_back( getDSRecord( *ksk, DNSSEC_SHA384 ) );
	}
        return result;
    }

    void ZoneSignerImp::initialize()
    {
        SSL_library_init();
    }

    std::vector<std::shared_ptr<PublicKey>> ZoneSignerImp::getKSKPublicKeys() const
    {
	std::vector<std::shared_ptr<PublicKey> > keys;
	for ( auto ksk : mKSKs )
	    keys.push_back( ksk->getPublicKey() );
	return keys;
    }

    std::vector<std::shared_ptr<PublicKey>> ZoneSignerImp::getZSKPublicKeys() const
    {
	std::vector<std::shared_ptr<PublicKey> > keys;
	for ( auto zsk : mZSKs )
	    keys.push_back( zsk->getPublicKey() );
	return keys;
    }

    /*******************************************************************************************
     * RSAPublicKeyImp
     *******************************************************************************************/

    RSAPublicKeyImp::RSAPublicKeyImp( const PacketData &exp, const PacketData &mod )
	: exponent( exp ), modulus( mod )
    {}

    std::string RSAPublicKeyImp::toString() const
    {
	std::ostringstream os;
	std::string exponent_base64, modulus_base64;
	encodeToBase64( exponent, exponent_base64 );
	encodeToBase64( modulus,  modulus_base64 );

	os << "exponent: " << exponent_base64 << ", "
	   << "modulus: "  << modulus_base64;

	return os.str();
    }

    static void copyFactor( const PacketData &src,
			    PacketData &dst )
    {
	dst.clear();
	auto i = src.begin();
	for ( ; *i == 0 && i != src.end() ; i++ ); // skip front 0x00. see RFC3110 2
	for ( ; i != src.end() ; i++ )
	    dst.push_back( *i );
    }

    PacketData RSAPublicKeyImp::getDNSKEYFormat() const
    {
	PacketData result;
	PacketData exponent_tmp, modulus_tmp;

	copyFactor( exponent, exponent_tmp );
	copyFactor( modulus,  modulus_tmp );
	
	uint32_t exponent_size = exponent_tmp.size();
	if ( exponent_size < 0x0100 ) {
	    result.push_back( exponent_size );
	}
	else {
	    result.push_back( 0 );
	    result.push_back( ( exponent_size & 0xff00 ) >>  8 );
	    result.push_back( ( exponent_size & 0x00ff ) >>  0 );
	}

	result.insert( result.end(), exponent_tmp.begin(), exponent_tmp.end() );
	result.insert( result.end(), modulus_tmp.begin(),  modulus_tmp.end() );
	return result;
    }


    /*******************************************************************************************
     * ECDSAPublicKeyImp
     *******************************************************************************************/

    ECDSAPublicKeyImp::ECDSAPublicKeyImp( const PacketData &q )
	: mQ( q )
    {}

    ECDSAPublicKeyImp::ECDSAPublicKeyImp( const uint8_t *p, ssize_t size )
        : mQ( p, p + size )
    {}


    std::string ECDSAPublicKeyImp::toString() const
    {
	std::ostringstream os;
	std::string q_base64;
	encodeToBase64( mQ, q_base64 );

	os << "Q: " << q_base64;

	return os.str();
    }

    PacketData ECDSAPublicKeyImp::getDNSKEYFormat() const
    {
	return mQ;
    }


}

