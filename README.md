# HachingAlgo
Implementation of SHA1, MD5 &amp; SHA3.

##1  Installing HachingAlgo and generate executables
```
$> git clone https://github.com/pouwapouwa/HachingAlgo.git
$> cd HachingAlgo
$> make
```

##2 Generate Report (in French)
```
$> make report
$> cd Documents
$> open Memoire.pdf
```

##3 Running Test

Compare executable's result with sha1sum, md5sum & sha3sum.

```
$> make test
```

##4 Concerning sha3sum

By default, sha3sum is not already installed. I would advise to get it from Digest::SHA3 withn CPAN, in Perl.
