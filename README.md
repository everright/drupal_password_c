# drupal_password_c
Ported the drupal password hash with C.

Background
----------

My project need to migrate millions of users from old system into new Drupal system, so i developed mysql udf version with C of drupal password hash, then we can use mysql function to hash password when import users by MySQL csv load feature.

This is my first time to learn the C language, of course, is also the first to write programs using the C language. May be this isn't a good code, please forgive me.

Requirements
------------

* openssl

Tested on
---------

* Linux
* Mac OS X

Support
-------

* Drupal 7
* Drupal 8

Complie
-------

    $ gcc drupal_password.c -lcrypto -o drupal_password

Usage
-----

Encrypt plain-text password

    $ ./drupal_password your_password

Encrypt md5 password

    $ ./drupal_password your_md5_hashed_password 11