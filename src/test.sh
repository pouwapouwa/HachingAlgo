#!/bin/sh

EXEC=false
EXECUTABLE=SHA1
if [ "$1" ]; then
    EXECUTABLE=$1
fi
TEXTFILE=sha1.c
SHA3S="echo Try to get sha3sum with cpan --> libdigest-sha3-perl"
export TIMEFORMAT='%3R'

for filename in *; do
    if [ $filename = "SHA1" ]; then
	EXEC=true
    fi
done

OS="`uname`"

if [ "$OS" = "Linux" ]; then
    SHA1S=sha1sum
    MD5S=md5sum
elif [ "$OS" = "Darwin" ]; then
    SHA1S=shasum
    MD5S=md5
else
    echo "OS not known by this script"
    exit
fi

Throughput () {
    echo -n "$3 : "
    echo -n "" 1> test.bc
    echo -n `(du  $2 | cut -f1)` 1>> test.bc
    echo -n "/" 1>> test.bc
    time ($1 $2 >> /dev/null 2>&1) 2>> test.bc
    echo "halt" 1>> test.bc
    echo -n `($1 $2 || $SHA3S) 2> /dev/null`
    if [ "$4" ]; then printf " %s" $4
    fi
    echo " --" `bc -q test.bc 2> /dev/null` "Ko/s"
    }

if [ "$EXEC" = "true" ]; then
    echo "----------- TESTING HASH FUNCTIONS -----------"
    
    printf '\nSHA1 hashing an executable with our algorithm and sha1sum: \n'
    Throughput './SHA1 -i' $EXECUTABLE "SHA1   " $EXECUTABLE
    Throughput $SHA1S $EXECUTABLE $SHA1S 
    
    printf '\nSHA1 hashing a text file with our algorithm and sha1sum: \n'
    Throughput './SHA1 -i' $TEXTFILE "SHA1   " $TEXTFILE
    Throughput $SHA1S $TEXTFILE $SHA1S
    
    printf '\nMD5 hashing an executable with our algorithm and md5sum: \n'
    Throughput './MD5 -i' $EXECUTABLE "MD5   " $EXECUTABLE
    Throughput $MD5S $EXECUTABLE $MD5S
    
    printf '\nMD5 hashing a text file with our algorithm and md5sum: \n'
    Throughput './MD5 -i' $TEXTFILE "MD5   " $TEXTFILE
    Throughput $MD5S $TEXTFILE $MD5S

    printf '\nSHA3 hashing an executable with our algorithm: \n'
    Throughput './SHA3 -i' $EXECUTABLE "SHA3   " $EXECUTABLE
    (Throughput sha3sum $EXECUTABLE "sha3sum") || $SHA3S
    
    printf '\nSHA3 hashing a text file with our algorithm: \n'
    Throughput './SHA3 -i' $TEXTFILE "SHA3   " $TEXTFILE
    (Throughput sha3sum $TEXTFILE "sha3sum") || $SHA3S

    echo "----------------------------------------------"
    rm test.bc
    
else
    echo $EXECUTABLE "does not exist"
fi
