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

my $resultset = await $client.query('SELECT * FROM foo WHERE id = $1', [ 42 ]);
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

  * TypeMap :$typemap = TypeMap::JSON

    This is the typemap that is used to translate between Raku's and Postgres' typesystem. The default mapping supports common built-in types such as strings, numbers, bools, dates, datetimes, blobs, arrays and hashes. Other options include `TypeMap::Native` if you want arrays to map to postgres' native arrays and `TypeMap::Minimal` if one wants all values to map to strings.

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

prepare($query, :@input-types --> Promise[PreparedStatement])
-------------------------------------------------------------

This prepares the query, and returns a Promise to the PreparedStatement object. `@input-types` can be used to pass on hints about the types you're passing in during `execute`.

method get-channel(Str $name --> Supply)
----------------------------------------

This returns the `Supply` for the given channel.

add-enum-type(Str $name, ::Enum --> Promise)
--------------------------------------------

This looks up the `oid` of postgres enum `$name`, and adds an appriopriate `Type` object to the typemap to convert it from/to `Enum`.

add-composite-type(Str $name, ::Composite, Bool :$positional --> Promise)
-------------------------------------------------------------------------

This looks up the `oid` of the postgres composite type <$name>, and maps it to `Composite`; if `$positional` is set it will use positional constructor arguments, otherwise named ones are used; it will use a heuristic by default.

add-custom-type(Str $name, ::Custom, &from-string?, &to-string?)
----------------------------------------------------------------

This adds a custom converter from postgres type `$name` from/to Raku type `Custom`. By default `&from-string` will do a coercion, and `&to-string` will do stringification.

startTls(--> Blob)
------------------

This will return the marker that should be written to the server to start upgrading the connection to use TLS. If the server responds with a single `S` byte the proposal is accepted and the client is expected to initiate the TLS handshake. If the server responds with an `N` it is rejected, and the connection proceeds in cleartext.

terminate(--> Nil)
------------------

This sends a message to the server to terminate the connection

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

object-rows(::Class, Bool :$positional --> Supply[Class])
---------------------------------------------------------

This returns a Supply of objects of class `Class`, each object is constructed form the row hash unless positional is true in which case it's constructed from the row list.

arrays
------

This returns a sequence of arrays of results from all rows. This may `await`.

array
-----

This returns a single array of results from one row. This may `await`.

value
-----

This returns a single value from a single row. This may `await`.

hashes
------

This returns a sequence of hashes of the results from all rows. This may `await`.

hash
----

This returns a single hash of the results from one rows. This may `await`.

objects(::Class, Bool :$positional)
-----------------------------------

This returns a sequence of objects based on all the rows. This may `await`.

object(:Class, Bool :$positional)
---------------------------------

This returns a single object based on a single row. This may `await`.

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

