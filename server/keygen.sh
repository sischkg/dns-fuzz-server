#!/bin/sh

OPENSSL=openssl

zone=$1
algo=$2
base=$3

if [ x"" = x"$zone" ]
then
    echo "Usage: $0 [zone] [algorithm] [dirname]"
    exit 1
fi

if [ x"" = x"$algo" ]
then
    algo=RSASHA1
fi
case $algo in
RSASHA1)
    ;;
RSASHA256)
    ;;
ECDSAP256SHA256)
    ;;
*)
    echo "Unknown algorithm $algo"
    exit 1
    ;;
esac

if [ x"" = x"$base" ]
then
  base=`pwd`
fi
keys=$base/keys

key_filename()
{
    zone=$1
    type=$2
    index=$3

    if [ x$zone = x"." ] ; then
	    zone=root
    fi

    echo "$keys/$zone.$type.$index.key"
}

config_filename()
{
    zone=$1
    type=$2

    if [ x$zone = x"." ] ; then
	    zone=root
    fi
    echo "$base/$zone.$type.yaml"
}

generate_config()
{
    zone=$1
    type=$2
    period_sec=$3
    algo=$4
    count=$5

    not_before=`date +%s`
    not_after=`expr $not_before \+ $period_sec`

    config_file=`config_filename $zone $type`

    i=0
    while [ $i -lt $count ]
    do
        key_file=`key_filename $zone $type $i`
        cat <<-END_TEMPLATE >> $config_file
	- domain: $zone
	  type: $type
	  algorithm: $algo
	  not_before: $not_before
	  not_after: $not_after
	  key_file: $key_file
END_TEMPLATE
        i=`expr $i + 1`
    done
}

generate_private_key()
{
    zone=$1
    type=$2
    algo=$3
    count=$4
    
    i=0
    while [ $i -lt $count ]
    do
        key_file=`key_filename $zone $type $i`

        if [ x$algo = xECDSAP256SHA256 ]
        then
            $OPENSSL ecparam -genkey -name prime256v1 -out $key_file
        else
            key_size=1024
            if [ x$type = x"ksk" ]
            then
                key_size=2048
            fi
            rm -f $key_file
            $OPENSSL genrsa -out $key_file $key_size
        fi
        i=`expr $i + 1`
    done
}


generate_keys()
{
    zone=$1
    algo=$2
    count=$3
    generate_config $zone ksk 864000 $algo $count
    generate_config $zone zsk 864000 $algo $count
    generate_private_key $zone ksk $algo  $count
    generate_private_key $zone zsk $algo  $count
}


init_config()
{
    zone=$1
    type=$2

    config_file=`config_filename $zone $type`
    echo --- > $config_file
}

init_configs()
{
    zone=$1
    init_config $zone ksk
    init_config $zone zsk
}

mkdir -p $keys

init_configs $zone
generate_keys $zone $algo 1

