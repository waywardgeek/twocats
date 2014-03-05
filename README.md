TigerKDF
=======

TigerKDF is a sequential memory and compute time hard key derivation function that
maximizes an attackers time*memory cost for guessing passwords.  Christian Forler and
Alexander Peslyak (aka SolarDesigner) provided most of the ideas that I have combined in
TigerKDF.  While they may not want credit for this work, it belongs to them more than me.

Please read TigerKDF.odt for a description of the algorithm and credits for ideas.

License
-------

I, Bill Cox, wrote this code in 2014, and place this code into the public domain.  There
are no hidden back-doors or intentional weaknesses, and I believe it violates no patents.
I will file no patents on any material in this project.

TigerKDF includes PBKDF2 code which I copied from the scrypt source code, and which is
released under the BSD license, and tigerkdf-test.c was copied from Catena's
catena_test_vectors.c and is released under the MIT license.
