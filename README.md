pg_sslstatus
============

pg_sslstatus is a simple extension to PostgreSQL that allows an
administrator to view the SSL status of different connections. It
shows whether SSL is in force, the negotiated SSL parameters, and
information about the (optional) client certificate on the connection.

Building
--------
pg_sslstatus is built with pgxs. To install, just run:

    $ make
    $ sudo make install

This assumes that the basic compilers and PostgreSQL development
packages are installed on your system. On Debian for example, you can
install those using:

    $ sudo apt-get install build-essential postgresql-server-dev-all

Installing
----------
Once built, the extension needs to be installed in the server. Since
it's packaged as an extension, it's a simple command in psql:

    postgres=# CREATE EXTENSION pg_sslstatus;
    CREATE EXTENSION

This will create a view and an underlying function.

The library also needs to be loaded in `shared_preload_libraries`, by
setting the parameter in `postgresql.conf`:

    shared_preload_libraries = 'pg_sslinfo'


Using
-----
All SSL information is exposed through a simple view:

    postgres=# SELECT * FROM pg_sslstatus;
      pid  | ssl | bits | compression | version |        cipher        |                         clientdn                         
    -------+-----+------+-------------+---------+----------------------+----------------------------------------------------------
     27286 | t   |  256 | f           | TLSv1   | ECDHE-RSA-AES256-SHA | 
     26682 | t   |  256 | t           | TLSv1   | ECDHE-RSA-AES256-SHA | /C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=magnus
     26693 | f   |      |             |         |                      | 
    (3 rows)

The `pid` field can be joined to either `pg_stat_activity` or
`pg_stat_replication` to connect the information with further details
about the connection.
