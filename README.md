NOELKDF
=======

NoelKDF is a sequential memory and compute time hard key derivation function that
maximizes an attackers time*memory cost for guessing passwords.  Christian Forler and
Alexander Peslyak (aka SolarDesigner) provided most of the ideas that I have combined in
NoelKDF.  While they may not want credit for this work, it belongs to them more than me.

Please read NoelKDF.odt for a description of the algorithm and credits for ideas.

License
-------

I, Bill Cox, wrote this code in January of 2014, and place this code into the public
domain.  There are no hidden back-doors or intentional weaknesses, and I believe it
violates no patents.  I will file no patents on any material in this project.

NoelKDF includes sha.c and sha.h which I copied from the scrypt source code, and which is
released under the BSD license, and noelkdf-test.c was copied from Catena's
catena_test_vectors.c and is released under the MIT license.

Files
-----
LICENSE                                 License description for NoelKDF
main.c                                  Simple wrapper around NoelKDF for testing from the command line
Makefile                                Makefile for NoelKDF
noelkdf-common.c                        Common code for different versions (ref vs pthread) of NoelKDF
noelkdf.h                               NoelKDF header file
NoelKDF.pdf                             PDF paper describing NoelKDF
noelkdf-pthread.c                       Threaded version of NoelKDF
noelkdf.py                              Python2 version of NoelKDF - just for reference
noelkdf-ref.c                           Reference version of NoelKDF hashing function
noelkdf-test.c                          Some MIT licensed code, originally from Catena,
                                        used for testing and vector generation
predict/main.c                          Pebbling algorithm for testing memory-hard KDF performance
predict/Makefile                        Predict Makefile
predict/Pebble.dd                       DataDraw database description file (http://datadraw.sourceforge.net)
predict/pedatabase.c                    Generated DataDraw C file
predict/pedatabase.h                    Generated DataDraw header file
predict/README                          Brief description of predict
quick_check                             Bash script to do a quick sanity check
run_noelkdf                             Simple wrapper script for running NoelKDF
sha256.c                                BSD licensed file for PBKDF2-SHA256 from scrypt
sha256.h                                BSD licensed header file for PBKDF2-SHA256 from scrypt
test_vectors                            File of expected hashes for many different parameter inputs
                                        Created by running noelkdf-test
