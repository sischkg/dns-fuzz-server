#ifndef ZONE_SIGNER_HPP
#define ZONE_SIGNER_HPP

#include "dns.hpp"
#include "zone.hpp"

namespace dns
{
    class ZoneSignerImp;
    class PrivateKeyImp;
    class PublicKey;
    class RSAPublicKey;
    class RSAPublicKeyImp;
    class ECDSAPublicKey;
    class ECDSAPublicKeyImp;

    enum KeyType {
        KSK = 257,
        ZSK = 256,
    };

    enum HashAlgorithm {
	DNSSEC_SHA1   = 1,
	DNSSEC_SHA256 = 2,
	DNSSEC_SHA384 = 4,
    };

    enum SignAlgorithm {
	DNSSEC_RSASHA1     = 5,
	DNSSEC_ECDSASHA256 = 13,
	DNSSEC_ECDSASHA384 = 14,
    };
    
    class PublicKey {
    public:
        virtual ~PublicKey() {}
        virtual std::string toString() const = 0;
        virtual std::vector<uint8_t> getDNSKEYFormat() const = 0;
    };
    
    class RSAPublicKey : public PublicKey
    {
    public:
        RSAPublicKey( const std::vector<uint8_t> &exp, const std::vector<uint8_t> &mod );
	
        virtual std::string toString() const;
        const std::vector<uint8_t> &getExponent() const;
        const std::vector<uint8_t> &getModulus() const;
        virtual std::vector<uint8_t> getDNSKEYFormat() const;
    private:
	std::shared_ptr<RSAPublicKeyImp> mImp;
    };
	
    class ECDSAPublicKey : public PublicKey
    {
    public:
        ECDSAPublicKey( const std::vector<uint8_t> &k );
	
        virtual std::string toString() const;
        virtual std::vector<uint8_t> getDNSKEYFormat() const;
    private:
	std::shared_ptr<ECDSAPublicKeyImp> mImp;
    };
	

    class ZoneSigner
    {
    public:
        ZoneSigner( const Domainname &d, const std::string &ksks, const std::string &zsk );

	std::shared_ptr<RRSet> signRRSet( const RRSet & ) const;
	std::shared_ptr<RRSet> signDNSKEY( TTL ttl ) const;

	std::vector<std::shared_ptr<PublicKey>> getKSKPublicKeys() const;
	std::vector<std::shared_ptr<PublicKey>> getZSKPublicKeys() const;

        std::vector<std::shared_ptr<RecordDS>> getDSRecords() const;
        std::vector<std::shared_ptr<RecordDNSKEY>> getDNSKEYRecords() const;

        static void initialize();

    private:
        std::shared_ptr<ZoneSignerImp> mImp;
    };
}

#endif