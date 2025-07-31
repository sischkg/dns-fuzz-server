
base=`dirname $0`
keys=$base/keys
zone=fuzz.kinokodon.jp
zonefile=$zone.zone

dnssec-signzone -O full -S -x -K $keys -d $base -e +30d -r /dev/urandom -N unixtime -f $base/$zonefile.signed -o $zone $base/$zonefile


zone=child.siskrn.co
zonefile=$zone.zone

dnssec-signzone -O full -S -x -K $keys -d $base -e +30d -r /dev/urandom -N unixtime -f $base/$zonefile.signed -o $zone $base/$zonefile
