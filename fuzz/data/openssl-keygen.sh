#!/bin/sh

ZONE=child.siskrn.co
KSK_LENGTH=2048
ZSK_LENGTH=2048

base=`dirname $0`
ksk=$base/$ZONE.ksk.key
zsk=$base/$ZONE.zsk.key

rm -f $ksk $zsf
echo "" | openssl genrsa -out $ksk $KSK_LENGTH
echo "" | openssl genrsa -out $zsk $ZSK_LENGTH


