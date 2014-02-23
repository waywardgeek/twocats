TigerKDF
=======

TigerKDF is a sequential memory and compute time hard key derivation function that
maximizes an attackers time*memory cost for guessing passwords.  Christian Forler and
Alexander Peslyak (aka SolarDesigner) provided most of the ideas that I have combined in
TigerKDF.  While they may not want credit for this work, it belongs to them more than me.

Please read TigerKDF.odt for a description of the algorithm and credits for ideas.

License
-------

I, Bill Cox, wrote this code in January of 2014, and place this code into the public
domain.  There are no hidden back-doors or intentional weaknesses, and I believe it
violates no patents.  I will file no patents on any material in this project.

TigerKDF includes sha.c and sha.h which I copied from the scrypt source code, and which is
released under the BSD license, and tigerkdf-test.c was copied from Catena's
catena_test_vectors.c and is released under the MIT license.

Files
-----
COPYING                                 License description for TigerKDF
main.c                                  Simple wrapper around TigerKDF for testing from the command line
Makefile                                Makefile for TigerKDF
tigerkdf-common.c                       Common code for different versions (ref vs pthread) of TigerKDF
tigerkdf.h                              TigerKDF header file
TigerKDF.pdf                            PDF paper describing TigerKDF
tigerkdf-pthread.c                      Threaded version of TigerKDF
tigerkdf.py                             Python2 version of TigerKDF - just for reference
tigerkdf-ref.c                          Reference version of TigerKDF hashing function
tigerkdf-test.c                         Some MIT licensed code, originally from Catena,
                                        used for testing and vector generation
predict/main.c                          Pebbling algorithm for testing memory-hard KDF performance
predict/Makefile                        Predict Makefile
predict/Pebble.dd                       DataDraw database description file (http://datadraw.sourceforge.net)
predict/pedatabase.c                    Generated DataDraw C file
predict/pedatabase.h                    Generated DataDraw header file
predict/README                          Brief description of predict
quick_check                             Bash script to do a quick sanity check
run_tigerkdf                            Simple wrapper script for running TigerKDF
sha256.c                                BSD licensed file for PBKDF2-SHA256 from scrypt
sha256.h                                BSD licensed header file for PBKDF2-SHA256 from scrypt
test_vectors                            File of expected hashes for many different parameter inputs
                                        Created by running tigerkdf-test
