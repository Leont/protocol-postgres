[![Actions Status](https://github.com/Leont/protocol-postgres/workflows/test/badge.svg)](https://github.com/Leont/protocol-postgres/actions)

Name
====

Protocol::Postgres - a sans-io postgresql client

Synopsis
========

```raku
use v6.d;
use Protocol::Postgres;

my $socket = await IO::Socket::Async.connect($host, $port);
my $client = Protocol::Postgres::Client.new;
$socket.Supply(:bin).act({ $client.incoming-data($^data) });
$client.outbound-data.act({ $socket.write($^data) });

await $client.startup($user, $database, $password);

my $resultset = await $client.query('SELECT * FROM foo WHERE id = $1', 42);
react {
	whenever $resultset.hash-rows -> (:$name, :$description, :$id) {
		say "$name is $description";
	}
}
```

Description
===========

Protocol::Postgres is sans-io implementation of (the client side of) the postgresql protocol. It is typically used through the `Protocol::Postgres::Client` class.

Client
======

`Protocol::Postgres::Client` has the following methods

new(--> Protocol::Postgres::Client)
-----------------------------------

This creates a new postgres client. It supports one optional named argument:

  * TypeMap :$typemap = TypeMap::Standard

    This is the typemap that is used to translate between Raku's and Postgres' typesystem. The default mapping supports common built-in types such as strings, numbers, bools, dates, datetimes and blobs. `TypeMap::Stringy` is also available if one wants all values to map to strings.

outgoing-data(--> Supply)
-------------------------

This returns a `Supply` of `Blob`s to be written to the server.

incoming-data(Blob --> Nil)
---------------------------

This consumes bytes received from the server.

startup($user, $database?, $password? --> Promise)
--------------------------------------------------

This starts the handshake to the server. `$database` may be left undefined, the server will use `$user` as database name. If a `$password` is defined, any of clearnext, md5 or SCRAM-SHA-256 based authentication is supported.

The resulting promise will finish when the connection is ready for queries.

query($query, @bind-values --> Promise)
---------------------------------------

This will issue a query with the given bind values, and return a promise to the result.

For fetching queries such as `SELECT` the result in the promise will be a `ResultSet` object, for manipulation (e.g. `INSERT`) and definition (e.g. `CREATE`) queries it will result a string describing the change (e.g. `DELETE 3`). For a `COPY FROM` query it will `Supply` with the data stream, and for `COPY TO` it will be a `Supplier`.

Both the input types and the output types will be typemapped between Raku types and Postgres types using the typemapper.

query-multiple($query --> Supply[ResultSet])
--------------------------------------------

This will issue a complex query that may contain multiple statements, but can not use bind values. It will return a `Supply` to the results of each query.

prepare($query --> Promise[PreparedStatement])
----------------------------------------------

This prepares the query, and returns a Promise to the PreparedStatement object.

startTls(--> Blob)
------------------

This will return the marker that should be written to the server to start upgrading the connection to use TLS. If the server responds with a single `S` byte the proposal is accepted and the client is expected to initiate the TLS handshake. If the server responds with an `N` it is rejected, and the connection proceeds in cleartext.

terminate(--> Nil)
------------------

This sends a message to the server to terminate the connection

notifications(--> Supply[Notification])
---------------------------------------

This returns a supply with all notifications that the current connection is subscribed to. Channels can be subscribed using the `LISTEN` command, and messages can be sent using the `NOTIFY` command.

disconnected(--> Promise)
-------------------------

This returns a `Promise` that must be be kept or broken to signal the connection is lost.

process-id(--> Int)
-------------------

This returns the process id of the backend of this connection. This is useful for debugging purposes and for notifications.

get-parameter(Str $name --> Str)
--------------------------------

This returns various parameters, currently known parameters are: `server_version`, `server_encoding`, `client_encoding`, `application_name`, `default_transaction_read_only`, `in_hot_standby`, `is_superuser`, `session_authorization`, `DateStyle`, `IntervalStyle`, `TimeZone`, `integer_datetimes`, and `standard_conforming_strings`.

ResultSet
=========

A `Protocol::Postgres::ResultSet` represents the results of a query, if any.

columns(--> List)
-----------------

This returns the column names for this resultset.

rows(--> Supply[List])
----------------------

This returns a Supply of rows. Each row is a list of values.

hash-rows(--> Supply[Hash])
---------------------------

This returns a Supply of rows. Each row is a hash with the column names as keys and the row values as values.

PreparedStatement
=================

A `Protocol::Postgres::PreparedStatement` represents a prepated statement. Its reason of existence is to call `execute` on it.

execute(@arguments --> Promise[ResultSet])
------------------------------------------

This runs the prepared statement, much like the `query` method would have done.

close()
-------

This closes the prepared statement.

columns()
---------

This returns the columns of the result once executed.

Notification
============

`Protocol::Postgres::Notification` has the following methods:

sender(--> Int)
---------------

This is the process-id of the sender

channel(--> Str)
----------------

This is the name of the channel that the notification was sent on

message(--> Str)
----------------

This is the message of the notification

Author
======

Leon Timmermans <fawaka@gmail.com>

Copyright and License
=====================

Copyright 2022 Leon Timmermans

This library is free software; you can redistribute it and/or modify it under the Artistic License 2.0.

