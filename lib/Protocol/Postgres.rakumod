unit module Protocol::Postgres:ver<0.0.1>:auth<cpan:LEONT>;

enum ErrorField (:SeverityLocalized(83), :Severity(86), :ErrorCode(67), :Message(77), :Detail(68), :Hint(72), :Position(80), :InternalPosition(112), :InternalQuery(113), :Where(87), :SchemaName(115), :Table(116), :Column(99), :Datatype(100), :Constraint(110), :File(70), :Line(76), :Routine(82));

package X {
	our class Client is Exception {
		has Str:D $.message is required;
		method new(Str:D $message) {
			self.bless(:$message);
		}
	}

	our class Server is Exception {
		has Str:D $.prefix is required;
		has Str:D %.values{ErrorField} is required;
		method new(Str:D $prefix, Hash[Str,ErrorField] $values) {
			self.bless(:$prefix, :$values);
		}
		method message(--> Str) {
			"$!prefix: %!values{Message}";
		}
	}
}

class EncodeBuffer {
	has Buf:D $!buffer = Buf.new;
	method buffer() { Blob.new($!buffer) }

	method write-int32(Int:D $value --> Nil) {
		$!buffer.write-int32($!buffer.elems, $value, BigEndian);
	}
	method write-int16(Int:D $value --> Nil) {
		$!buffer.write-int16($!buffer.elems, $value, BigEndian);
	}
	method write-int8(Int:D $value --> Nil) {
		$!buffer.write-int8($!buffer.elems, $value);
	}
	method write-buffer(Blob:D $value --> Nil) {
		$!buffer ~= $value;
	}
	method write-string(Str:D $value --> Nil) {
		$!buffer ~= $value.encode ~ Blob(0);
	}
}

class DecodeBuffer {
	has Blob:D $.buffer is required;
	has Int $!pos = 0;

	method !assert-more-bytes(Int $count) {
		die X::Client.new('Incomplete packet') if $!pos + $count > $!buffer.elems;
	}

	method read-int32() {
		self!assert-more-bytes(4);
		my $result = $!buffer.read-int32($!pos, BigEndian);
		$!pos += 4;
		$result;
	}
	method read-int16() {
		self!assert-more-bytes(2);
		my $result = $!buffer.read-int16($!pos, BigEndian);
		$!pos += 2;
		$result;
	}
	method read-int8() {
		self!assert-more-bytes(1);
		my $result = $!buffer.read-int8($!pos++);
		$result;
	}
	method peek-int8() {
		self!assert-more-bytes(1);
		$!buffer.read-uint8($!pos);
	}
	method read-string() {
		my $current = $!pos;
		my $end = $!buffer.elems;
		$current++ while $current < $end and $!buffer[$current] != 0;
		die X::Client.new('Incomplete packet') if $current == $end;
		my $result = $!buffer.subbuf($!pos, $current - $!pos);
		$!pos = $current + 1;
		$result.decode;
	}
	method read-buffer(Int $length) {
		self!assert-more-bytes($length);
		my $result = $!buffer.subbuf($!pos, $length);
		$!pos += $length;
		$result;
	}

	method remaining-bytes() {
		$.buffer.elems - $!pos;
	}
}

role Serializable {
	method type(--> Any:U) { ... }
	method encode(EncodeBuffer $buffer, $value) { ... }
	method decode(DecodeBuffer $buffer) { ... }
}

our proto map-type(|) { * }
multi map-type(Serializable $type) { $type }

role Serializable::Integer does Serializable {
	method type() { Int }
	method size() { ... }
	has Int:D $.value is required;
	method COERCE(Int:D $value) {
		self.new(:$value);
	}
}

class Int32 does Serializable::Integer {
	method size(--> 4) {}
	method encode(EncodeBuffer $buffer, Int $value) {
		$buffer.write-int32($value);
	}
	method decode(DecodeBuffer $buffer) {
		$buffer.read-int32;
	}
}

multi map-type(Int:U) { Int32 }
multi map-type(Int:D $value) { Int32($value) }

class Int16 does Serializable::Integer {
	method size(--> 2) {}
	method encode(EncodeBuffer $buffer, Int $value) {
		$buffer.write-int16($value);
	}
	method decode(DecodeBuffer $buffer) {
		$buffer.read-int16;
	}
}

class Int8 does Serializable::Integer {
	method size(--> 1) {}
	method encode(EncodeBuffer $buffer, Int $value) {
		$buffer.write-int8($value);
	}
	method decode(DecodeBuffer $buffer) {
		$buffer.read-int8;
	}
}

class String does Serializable {
	method type() { Str }

	method encode(EncodeBuffer $buffer, Str $value) {
		$buffer.write-string($value);
	}
	method decode(DecodeBuffer $buffer) {
		$buffer.read-string;
	}
}
multi map-type(Str:U) { String }

class Tail does Serializable {
	method type() { Blob }

	method encode(EncodeBuffer $buffer, Blob $value) {
		$buffer.write-buffer($value);
	}
	method decode(DecodeBuffer $buffer) {
		$buffer.read-buffer($buffer.remaining-bytes);
	}
}

role Enum[Any:U $enum-type, Any:U $raw-encoding-type] does Serializable {
	my Serializable:U $encoding-type = map-type($raw-encoding-type);
	method type() { $enum-type }

	method encode(EncodeBuffer $buffer, Enumeration $value) {
		$encoding-type.encode($buffer, $value.value);
	}
	method decode(DecodeBuffer $buffer) {
		$enum-type($encoding-type.decode($buffer));
	}
}

role Sequence[Any:U $raw-element-type, Serializable::Integer:U $count-type = Int16] does Serializable {
	my Serializable:U $element-type = map-type($raw-element-type);
	method type() { Array[$element-type.type] }

	method encode(EncodeBuffer $buffer, @values) {
		$count-type.encode($buffer, @values.elems);
		for @values -> $value {
			$element-type.encode($buffer, $value);
		}
	}
	method decode(DecodeBuffer $buffer) {
		my $count = $count-type.decode($buffer);
		my @result = (^$count).map: { $element-type.decode($buffer) };
		self.type.new(@result);
	}
}
multi map-type(Array:U $array-type) { Sequence[$array-type.of] }

role VarByte[Serializable::Integer:U $count-type, Bool $inclusive = False] does Serializable {
	method type() { Blob }
	my $offset = $inclusive ?? $count-type.size !! 0;

	method encode(EncodeBuffer $buffer, Blob $value) {
		$count-type.encode($buffer, $value.elems + $offset);
		$buffer.write-buffer($value);
	}
	method decode(DecodeBuffer $buffer) {
		my $count = $count-type.decode($buffer) - $offset;
		$count >= 0 ?? $buffer.read-buffer($count) !! Blob;
	}
}
multi map-type(Blob:U) { VarByte[Int32] }

role Series[Any:U $raw-element-type] does Serializable {
	my $element-type = map-type($raw-element-type);
	method type() { Array[$element-type.type] }

	method encode(EncodeBuffer $buffer, @values) {
		for @values -> $value {
			$element-type.encode($buffer, $value);
		}
		$buffer.write-int8(0);
	}
	method decode(DecodeBuffer $buffer) {
		my @result;
		while $buffer.peek-int8 != 0 {
			@result.push($element-type.decode($buffer));
		}
		@result;
	}
}

role Mapping[Any:U $raw-key-type, Any:U $raw-value-type] does Serializable {
	my $key-type = map-type($raw-key-type);
	my $value-type = map-type($raw-value-type);
	method type() { Hash[$value-type.type, $key-type.type] }

	method encode(EncodeBuffer $buffer, $values) {
		for %($values).sort -> $foo (:$key, :$value) {
			$key-type.encode($buffer, $key);
			$value-type.encode($buffer, $value);
		}
		$buffer.write-int8(0);
	}
	method decode(DecodeBuffer $buffer) {
		my %result{Any};
		while $buffer.peek-int8 != 0 {
			my $key = $key-type.decode($buffer);
			my $value = $value-type.decode($buffer);
			%result{$key} = $value;
		}
		%result;
	}
}
multi map-type(Hash:U $hash-type) { Mapping[$hash-type.keyof, $hash-type.of] }

class Schema {
	has Pair @.elements is required;
	method new(*@raw-elements) {
		my @elements = @raw-elements.map(-> (:$key, :$value) { $key => map-type($value) });
		self.bless(:@elements);
	}
	method encode-to(EncodeBuffer $encoder, %attributes) {
		for @!elements -> (:$key, :$value) {
			my $result = $value ?? $value.value !! %attributes{$key};
			$value.encode($encoder, $result);
		}
	}
	method encode(%attributes --> Blob) {
		my $encoder = EncodeBuffer.new;
		self.encode-to($encoder, %attributes);
		$encoder.buffer;
	}
	method decode-from(DecodeBuffer $decoder --> Map) {
		my %result;
		for @!elements -> (:$key, :$value) {
			%result{$key} := $value.decode($decoder)
		}
		%result;
	}
	method decode(Blob $buffer --> Map) {
		my $decoder = DecodeBuffer.new(:$buffer);
		self.decode-from($decoder);
	}
}

role Object[Any:U $outer] does Serializable {
	method type() { $outer }
	method encode(EncodeBuffer $encoder, $value) {
		$outer.schema.encode-to($encoder, $value.Capture.hash);
	}
	method decode(DecodeBuffer $decoder) {
		$outer.new(|$outer.schema.decode-from($decoder));
	}
}

multi map-type(ErrorField) { Enum[ErrorField, Int8] }

enum Format <Text Binary>;
multi map-type(Format) { Enum[Format, Int16] }

enum RequestType (:Prepared(83), :Portal(80));
multi map-type(RequestType) { Enum[RequestType, Int8] }

enum QueryStatus (:Idle(73), :Transaction(84), :Error(69));
multi map-type(QueryStatus) { Enum[QueryStatus, Int8] }

class FieldDescription {
	my $schema = Schema.new((:name(Str), :table(Int32), :column(Int16), :type(Int32), :size(Int16), :modifier(Int32), :format(Format)));
	method schema() { $schema }
	has Str:D $.name is required;
	has Int:D $.table = 0;
	has Int:D $.column = 0;
	has Int:D $.type = 0;
	has Int:D $.size = 0;
	has Int:D $.modifier = 0;
	has Format $.format = Text;
}
multi map-type(FieldDescription) { Object[FieldDescription] }

role Packet::Base {
	method header() { ... }
	method !schema() { state $ = Schema.new }
	my $packet = Schema.new((:header(Int8), :payload(VarByte[Int32, True])));
	method encode(--> Blob) {
		my $header = self.header;
		my $payload = self!schema.encode(self.Capture.hash);
		$packet.encode({:$header, :$payload});
	}
	method decode(Blob $buffer --> Packet::Base) {
		self.bless(|self!schema.decode($buffer.subbuf(5)));
	}
}

role Packet::Authentication does Packet::Base {
	method header(--> 82) {}
	method type() { ... }
}

class Packet::AuthenticationOk does Packet::Authentication {
	method type(--> 0) {}
	method !schema() { state $ = Schema.new((:0type)) }
}
class Packet::AuthenticationKerberosV5 does Packet::Authentication {
	method type(--> 2) {}
	method !schema() { state $ = Schema.new((:2type)) }
}
class Packet::AuthenticationCleartextPassword does Packet::Authentication {
	method type( --> 3) {}
	method !schema() { state $ = Schema.new((:3type)) }
}
class Packet::AuthenticationMD5Password does Packet::Authentication {
	method type(--> 5) {}
	method !schema() { state $ = Schema.new((:5type, :salt(Tail))) }
	has Blob:D $.salt is required;
}
class Packet::AuthenticationSCMCredential does Packet::Authentication {
	method type(--> 7) {}
	method !schema() { state $ = Schema.new((:7type)) }
}
class Packet::AuthenticationGSSContinue does Packet::Authentication {
	method type(--> 8) {}
	method !schema() { state $ = Schema.new((:8type)) }
}
class Packet::AuthenticationSSPI does Packet::Authentication {
	method type(--> 9) {}
	method !schema() { state $ = Schema.new((:9type)) }
}
class Packet::AuthenticationSASL does Packet::Authentication {
	method type(--> 10) {}
	method !schema() { state $ = Schema.new((:10type, :mechanisms(Series[Str]))) }
	has Str:D @.mechanisms is required;
}
class Packet::AuthenticationSASLContinue does Packet::Authentication {
	method type(--> 11) {}
	method !schema() { state $ = Schema.new((:11type, :server-payload(Tail))) }
	has Blob:D $.server-payload is required;
}
class Packet::AuthenticationSASLFinal does Packet::Authentication {
	method type(--> 12) {}
	method !schema() { state $ = Schema.new((:12type, :server-payload(Tail))) }
	has Blob:D $.server-payload is required;
}

class Packet::BackendKeyData does Packet::Base {
	method header(--> 75) {}
	method !schema() { state $ = Schema.new((:process-id(Int), :secret-key(Int))) }
	has Int:D $.process-id is required;
	has Int:D $.secret-key is required;
}

class Packet::Bind does Packet::Base {
	method header(--> 66) {}
	method !schema() { Schema.new((:portal(Str), :name(Str), :formats(Array[Format]), :fields(Array[Blob]), :result-formats(Array[Format]))) }
	has Str:D $.portal = '';
	has Str:D $.name = '';
	has Format @.formats = ();
	has Blob @.fields = ();
	has Format @.result-formats = ();
}

class Packet::BindComplete does Packet::Base {
	method header(--> 50) {}
}

class Packet::Close does Packet::Base {
	method header(--> 67) {}
	method !schema() { state $ = Schema.new((:type(RequestType), :name(Str))) }
	has RequestType:D $.type is required;
	has Str:D $.name = '';
}

class Packet::CloseComplete does Packet::Base {
	method header(--> 51) {}
}

class Packet::CommandComplete does Packet::Base {
	method header(--> 67) {}
	method !schema() { state $ = Schema.new((:command(Str))) }
	has Str:D $.command is required;
}

class Packet::CopyData does Packet::Base {
	method header(--> 100) {}
	method !schema() { state $ = Schema.new((:row(Tail))) }
	has Blob:D $.row is required;
}

class Packet::CopyDone does Packet::Base {
	method header(--> 99) {}
}

class Packet::CopyFail does Packet::Base {
	method header(--> 102) {}
	method !schema() { state $ = Schema.new((:reason(Str))) }
	has Str:D $.reason is required;
}

class Packet::CopyInResponse does Packet::Base {
	method header(--> 71) {}
	method !schema() { state $ = Schema.new((:format(Enum[Format, Int8]), :row-formats(Array[Format]))) }
	has Format:D $.format = Text;
	has Int @.row-formats = ();
}

class Packet::CopyOutResponse does Packet::Base {
	method header(--> 72) {}
	method !schema() { state $ = Schema.new((:format(Enum[Format, Int8]), :row-formats(Array[Format]))) }
	has Format:D $.format = Text;
	has Int @.row-formats = ();
}

class Packet::CopyBothResponse does Packet::Base {
	method header(--> 87) {}
	method !schema() { state $ = Schema.new((:format(Enum[Format, Int8]), :row-formats(Array[Format]))) }
	has Format:D $.format = Text;
	has Int @.row-formats = ();
}

class Packet::DataRow does Packet::Base {
	method header(--> 68) {}
	method !schema() { state $ = Schema.new((:values(Array[Blob]))) }
	has Blob @.values is required;
}

class Packet::Describe does Packet::Base {
	method header(--> 68) {}
	method !schema() { state $ = Schema.new((:type(RequestType), :name(Str))) }
	has RequestType:D $.type = Portal;
	has Str:D $.name = '';
}

class Packet::EmptyQueryResponse does Packet::Base {
	method header(--> 73) {}
}

class Packet::ErrorResponse does Packet::Base {
	method header(--> 69) {}
	method !schema() { state $ = Schema.new((:values(Hash[Str, ErrorField]))) }
	has Str %.values{ErrorField} is required;
}

class Packet::Execute does Packet::Base {
	method header(--> 69) {}
	method !schema() { state $ = Schema.new((:name(Str), :maximum-rows(Int))) }
	has Str:D $.name = '';
	has Int:D $.maximum-rows = 0;
}

class Packet::Flush does Packet::Base {
	method header(--> 72) {}
}

class Packet::FunctionCall does Packet::Base {
	method header(--> 70) {}
	method !schema() { state $ = Schema.new((:object-id(Int), :formats(Array[Format]), :values(Array[Blob]), :result-format(Format))) }
	has Int:D $.object-id is required;
	has Format @.formats = ();
	has Blob @.values = ();
	has Format $.result-format = Text;
}

class Packet::FunctionCallResponse does Packet::Base {
	method header(--> 86) {}
	method !schema() { state $ = Schema.new((:value(Blob))) }
	has Blob:D $.value is required;
}

class Packet::GSSResponse does Packet::Base {
	method header(--> 112) {}
	method !schema() { state $ = Schema.new((:payload(Blob))) }
	has Blob:D $.payload is required;
}

class Packet::NegotiateProtocolVersion does Packet::Base {
	method header(--> 118) {}
	method !schema() { state $ = Schema.new((:newest-minor-version(Int))) }
	has Int:D $.newest-minor-version is required;
}

class Packet::NoData does Packet::Base {
	method header(--> 110) {}
}

class Packet::NoticeResponse does Packet::Base {
	method header(--> 78) {}
	method !schema() { state $ = Schema.new((:values(Hash[Str, ErrorField]))) }
	has Str %.values{ErrorField} is required;
}

class Packet::NotificationResponse does Packet::Base {
	method header(--> 65) {}
	method !schema() { state $ = Schema.new((:sender(Int), :channel(Str), :payload(Str))) }
	has Int:D $.sender is required;
	has Str:D $.channel is required;
	has Str:D $.payload is required;
}

class Packet::ParameterDescription does Packet::Base {
	method header(--> 116) {}
	method !schema() { state $ = Schema.new((:types(Array[Int]))) }
	has Int @.types is required;
}

class Packet::ParameterStatus does Packet::Base {
	method header(--> 83) {}
	method !schema() { state $ = Schema.new((:name(Str), :value(Str))) }
	has Str:D $.name is required;
	has Str:D $.value is required;
}

class Packet::Parse does Packet::Base {
	method header(--> 80) {}
	method !schema() { state $ = Schema.new((:name(Str), :query(Str), :oids(Array[Int]))) }
	has Str:D $.name = '';
	has Str:D $.query is required;
	has Int @.oids = ();
}

class Packet::ParseComplete does Packet::Base {
	method header(--> 49) {}
}

class Packet::PasswordMessage does Packet::Base {
	method header(--> 112) {}
	method !schema() { state $ = Schema.new((:password(Str))) }
	has Str:D $.password is required;
}

class Packet::PortalSuspended does Packet::Base {
	method header(--> 115) {}
}

class Packet::Query does Packet::Base {
	method header(--> 81) {}
	method !schema() { state $ = Schema.new((:query(Str))) }
	has Str:D $.query is required;
}

class Packet::ReadyForQuery does Packet::Base {
	method header(--> 90) {}
	method !schema() { state $ = Schema.new((:status(QueryStatus))) }
	has QueryStatus:D $.status is required;
}

class Packet::RowDescription does Packet::Base {
	method header(--> 84) {}
	method !schema() { state $ = Schema.new((:fields(Array[FieldDescription]))) }
	has FieldDescription @.fields is required;
}

class Packet::SASLInitialResponse does Packet::Base {
	method header(--> 112) {}
	method !schema() { state $ = Schema.new((:mechanism(Str), :initial-response(Blob))) }
	has Str:D $.mechanism is required;
	has Blob:D $.initial-response is required;
}

class Packet::SASLResponse does Packet::Base {
	method header(--> 112) {}
	method !schema() { state $ = Schema.new((:client-payload(Tail))) }
	has Blob:D $.client-payload is required;
}

class Packet::Sync does Packet::Base {
	method header(--> 83) {}
}

class Packet::Terminate does Packet::Base {
	method header(--> 88) {}
}

my sub get-decoder(Packet::Base $class) {
	$class.header => { $class.decode($^payload) }
}

my Callable %front-decoder = map &get-decoder, Packet::BackendKeyData, Packet::BindComplete, Packet::CloseComplete, Packet::CommandComplete, Packet::CopyData, Packet::CopyDone, Packet::CopyInResponse, Packet::CopyOutResponse, Packet::CopyBothResponse, Packet::DataRow, Packet::EmptyQueryResponse, Packet::ErrorResponse, Packet::FunctionCallResponse, Packet::NegotiateProtocolVersion, Packet::NoData, Packet::NoticeResponse, Packet::NotificationResponse, Packet::ParameterDescription, Packet::ParameterStatus, Packet::ParseComplete, Packet::PortalSuspended, Packet::ReadyForQuery, Packet::RowDescription;

%front-decoder{82} = -> $payload {
	state %authentication-map = map { .type => $_ }, Packet::AuthenticationOk, Packet::AuthenticationKerberosV5, Packet::AuthenticationCleartextPassword, Packet::AuthenticationMD5Password, Packet::AuthenticationSCMCredential, Packet::AuthenticationGSSContinue, Packet::AuthenticationSSPI, Packet::AuthenticationSASL, Packet::AuthenticationSASLContinue, Packet::AuthenticationSASLFinal;
	my $type = $payload.read-int32(5, BigEndian);
	%authentication-map{$type}.decode($payload);
}

my Callable %back-decoder = map &get-decoder, Packet::Bind, Packet::Close, Packet::CopyData, Packet::CopyDone, Packet::CopyFail, Packet::Execute, Packet::Flush, Packet::FunctionCall, Packet::GSSResponse, Packet::Parse, Packet::PasswordMessage, Packet::Query, Packet::SASLInitialResponse, Packet::SASLResponse, Packet::Sync, Packet::Terminate;

enum Side <Front Back>;

class PacketDecoder {
	has Buf:D $!buffer is required;
	has Callable %!decoder-for;

	submethod BUILD(Blob :$buffer, Side :$type = Front) {
		$!buffer = Buf.new($buffer // ());
		%!decoder-for = $type === Front ?? %front-decoder !! %back-decoder;
	}
	method add-data(Blob:D $data --> Nil) {
		$!buffer ~= $data;
	}
	method read-packet(--> Packet::Base) {
		return Packet::Base if $!buffer.elems < 5;
		my $length = $!buffer.read-int32(1, BigEndian);
		return Packet::Base if $!buffer.elems < 1 + $length;
		my $payload = $!buffer.subbuf(0, 1 + $length);
		$!buffer.subbuf-rw(0, 1 + $length) = Blob.new;
		my &decoder = %!decoder-for{$payload[0]} or die X::Client.new('Invalid message type ' ~ $payload.subbuf(0, 1).decode);
		decoder(Blob.new($payload));
	}
}

role OpenPacket::Base {
	my $packet = Schema.new((:payload(VarByte[Int32, True])));
	method encode(--> Blob) {
		my $payload = self!schema.encode(self.Capture.hash);
		$packet.encode({:$payload});
	}
	method decode(Blob $buffer --> OpenPacket::Base) {
		self.bless(|self!schema.decode($buffer.subbuf(4)));
	}
}

class OpenPacket::CancelRequest does OpenPacket::Base {
	method !schema() { state $ = Schema.new((:80877102id, :process-id(Int), :secret-key(Int))) }
	has Int:D $.process-id is required;
	has Int:D $.secret-key is required;
}

class OpenPacket::GSSENCRequest does OpenPacket::Base {
	method !schema() { state $ = Schema.new((:80877104id)) }
}

class OpenPacket::SSLRequest does OpenPacket::Base {
	method !schema() { state $ = Schema.new((:80877103id)) }
}

class OpenPacket::StartupMessage does OpenPacket::Base {
	method !schema() { state $ = Schema.new((:196608id, :parameters(Hash[Str, Str]))) }
	has Str %.parameters is required;
}

my role Protocol {
	proto method incoming-message(Packet::Base $packet) { * }
	multi method incoming-message(Packet::NoticeResponse $) {}
	method finished() {}
	method failed(%values) {}
}

role Authenticator {
	proto method incoming-message(Packet::Authentication $packet, Promise $startup-promise, &send-message) { * }
	multi method incoming-message(Packet::Authentication $packet, Promise $startup-promise, &send-message) {
		$startup-promise.break(X::Client.new('Unknown authentication method'));
		self;
	}
}

class Authenticator::Null does Authenticator {
	multi method incoming-message(Packet::Authentication $packet, Promise $startup-promise, &send-message) {
		$startup-promise.break(X::Client.new('Password required but not given'));
		self;
	}
}

my class Authenticator::SCRAM does Authenticator {
	has $.scram is required;
	multi method incoming-message(Packet::AuthenticationSASLContinue $ (:$server-payload), Promise $startup-promise, &send-message) {
		try {
			my $client-payload = $!scram.final-message($server-payload.decode).encode;
			CATCH { default {
				$startup-promise.break(X::Client.new("Invalid server message: {.message}"));
			}}
			send-message(Packet::SASLResponse.new(:$client-payload));
		}
		self;
	}
	multi method incoming-message(Packet::AuthenticationSASLFinal $ (:$server-payload), Promise $startup-promise, &send-message) {
		if not try $!scram.validate($server-payload.decode) {
			my $reason = 'Could not validate final server message: ' ~ ($! // 'did not verify');
			$startup-promise.break(X::Client.new($reason));
		}
		self;
	}
}

class Authenticator::Password does Authenticator {
	has Str:D $.user is required;
	has Str:D $.password is required;

	multi method incoming-message(Packet::AuthenticationCleartextPassword $, Promise $startup-promise, &send-message) {
		send-message(Packet::PasswordMessage.new(:$!password));
		self;
	}

	multi method incoming-message(Packet::AuthenticationMD5Password $ (:$salt), Promise $startup-promise, &send-message) {
		require OpenSSL::Digest <&md5>;
		if &md5 {
			my sub md5-hex(Str $input) { md5($input.encode('latin1')).list».fmt('%02x').join };
			my $first-hash = md5-hex($!password ~ $!user);
			my $second-hash = md5-hex($first-hash ~ $salt.decode('latin1'));
			my $password = 'md5' ~ $second-hash;
			send-message(Packet::PasswordMessage.new(:$password));
		} else {
			$startup-promise.break(X::Client.new('Could not load MD5 module'));
		}
		self;
	}

	multi method incoming-message(Packet::AuthenticationSASL $ (:@mechanisms), Promise $startup-promise, &send-message) {
		if any(@mechanisms) eq 'SCRAM-SHA-256' {
			require Auth::SCRAM::Async;
			my $class = ::('Auth::SCRAM::Async::Client');
			if $class !=== Any {
				my $scram = $class.new(:username($!user), :$!password, :digest(::('Auth::SCRAM::Async::SHA256')));
				my $initial-response = $scram.first-message.encode;
				send-message(Packet::SASLInitialResponse.new(:mechanism<SCRAM-SHA-256>, :$initial-response));
				return Authenticator::SCRAM.new(:$scram);
			} else {
				$startup-promise.break(X::Client.new('Could not load SCRAM module'));
			}
		} else {
			$startup-promise.break(X::Client.new("Client does not support SASL mechanisms: @mechanisms[]"));
		}
		self;
	}
}

my class Protocol::Authenticating does Protocol {
	has Authenticator:D $.authenticator is required;
	has Promise $.startup-promise is required;
	has &.send-message is required;

	multi method incoming-message(Packet::Authentication $authentication) {
		$!authenticator = $!authenticator.incoming-message($authentication, $!startup-promise, &!send-message);
	}

	method finished() { $!startup-promise.keep unless $!startup-promise }
	method failed(%values) { $!startup-promise.break(X::Server.new('Could not authenticate', %values)) }
}

role Type[Int:D $oid, Any:U $type] {
	method oid(--> Int) { $oid }
	method type-object() { $type }
	method format() { Text }

	method encode-to-text(Any:D $value) { ... }
	multi method encode(Text, Any:D $value) { self.encode-to-text($value).encode }
	multi method encode(Format, Any:U $value) { Blob }
	method decode-from-text(Str $string) { ... }
	multi method decode(Text, Blob:D $blob) { self.decode-from-text($blob.decode) }
	multi method decode(Format, Blob:U $blob) { self.type-object }
}
sub type-encode(Type $type, Any $value) {
	$type.encode($type.format, $value);
}

class Type::Bool does Type[16, Bool] {
	method encode-to-text(Bool(Any:D) $input) { $input ?? 't' !! 'f' }
	method decode-from-text(Str:D $string --> Bool) { $string eq 't' }
}

class Type::Blob does Type[17, Blob] {
	method format() { Binary }
	multi method encode(Binary, Blob $input) { $input }
	method encode-to-text(Blob $value) {
		Q{\x} ~ $value.decode('latin1').subst(/./, { .ord.fmt('%02x') }, :g);
	}
	multi method decode(Binary, Blob $input) { $input }
	multi method decode-from-text(Str $string) {
		if $string.starts-with(Q{\x}) {
			$string.substr(2).subst(/<xdigit>**2/, { :16(~$_).chr }, :g).encode('latin1');
		} else {
			$string.subst(q{''}, q{'}, :g).subst(Q{\\}, Q{\}, :g).subst(/ \\ (<[0..7]> ** 3) /, -> $/ { :8(~$1).chr }, :g).encode('latin1');
		}
	}
}

class Type::Int does Type[20, Int] {
	method encode-to-text(Int(Cool:D) $int) { ~$int }
	method decode-from-text(Str:D $string --> Int) { $string.Int }
}

class Type::Num does Type[701, Num] {
	method encode-to-text(Num(Cool:D) $num) { ~$num }
	method decode-from-text(Str:D $string --> Num) { $string.Num }
}

class Type::Rat does Type[1700, Rat] {
	method encode-to-text(Rat(Cool:D) $rat) { ~$rat }
	method decode-from-text(Str:D $string --> Rat) { $string.Rat }
}

class Type::Date does Type[1182, Date] {
	method encode-to-text(Date(Any:D) $date) { ~$date }
	method decode-from-text(Str:D $string --> Date) { $string.Date }
}

class Type::DateTime does Type[1184, DateTime] {
	my sub to-datetime(Str $string --> DateTime) { $string.subst(' ', 'T').DateTime }
	multi method encode-to-text(DateTime:D $datetime) { ~$datetime }
	multi method encode-to-text(Date:D $datetime) { ~$datetime.DateTime }
	multi method encode-to-text(Str:D $input) { ~to-datetime($input) }
	method decode-from-text(Str:D $string --> DateTime) { to-datetime($string) }
}

role Type::Array { ... }

my sub quote-string(Str:D $string) {
	'"' ~ $string.subst(Q{\}, Q{\\}, :g).subst(/\"/, '\\"', :g) ~ '"';
}
my sub encode-array($element, @values) {
	if $element ~~ Type::Array|Type::Int|Type::Num|Type::Rat {
		return '{' ~ @values.map({ $element.encode-to-text($^value) }).join(', ') ~ '}';
	} else {
		return '{' ~ @values.map({ quote-string($element.encode-to-text($^value)) }).join(', ') ~ '}';
	}
}

class Type::Default does Type[0, Str] {
	multi method encode-to-text(@input) is default { encode-array(Type::Default, @input) }
	multi method encode-to-text(Str(Any:D) $input) { $input }
	method decode-from-text(Str:D $input) { $input }
}

role Type::Array[::Element, Int $oid] does Type[0, Array] {
	method oid(--> Int) { $oid }
	method type-object() { Array[Element.type-object] }
	my grammar ArrayParser {
		rule TOP {
			^ <array> $
			{ make $<array>.made }
		}
		rule array {
			'{' ~ '}' <element>* % ','
			{ make eager $<element>».made }
		}
		rule element {
			[ <value=array> | <value=string> | <value=quoted> | <value=null> ]
			{ make $<value>.made }
		}
		token string {
			<-[",{}\ ]>+
			{ make Element.decode-from-text(~$/) }
		}
		token quoted {
			'"' ~ '"' [ <str> | \\ <str=.escaped> ]*
			{ make Element.decode-from-text($<str>».made.join) }
		}
		token str {
			 <-["\\]>+
			{ make ~$/ }
		}
		token escaped {
			<["\\]>
			{ make ~$/ }
		}
		token null {
			'NULL'
			{ make Element.type-object }
		}
	}
	method encode-to-text(@values) {
		encode-array(Element, @values);
	}
	method decode-from-text(Str $string) {
		ArrayParser.parse($string).made;
	}
}

role TypeMap {
	method for-type(Any --> Type) { ... }
	method for-oid(Int --> Type) { ... }
}

class TypeMap::Simple does TypeMap {
	multi method for-type(Cool) { Type::Default }
	multi method for-type(Blob) { Type::Blob }
	multi method for-type(Bool) { Type::Bool }
	multi method for-type(Int) { Type::Int }
	multi method for-type(Num) { Type::Num }
	multi method for-type(DateTime) { Type::DateTime }
	multi method for-type(Date) { Type::Date }
	multi method for-type(Rat) { Type::Rat }
	multi method for-type(Array $array) { Type::Array[Type::Default, 1009] }
	multi method for-type(Array[Bool] $array) { Type::Array[Type::Bool, 1000] }
	multi method for-type(Array[Blob] $array) { Type::Array[Type::Blob, 1001] }
	multi method for-type(Array[Int] $array) { Type::Array[Type::Int, 1016] }
	multi method for-type(Array[Num] $array) { Type::Array[Type::Num, 1022] }
	multi method for-type(Array[Date] $array) { Type::Array[Type::Date, 1082] }
	multi method for-type(Array[DateTime] $array) { Type::Array[Type::DateTime, 1085] }

	multi method for-oid(Int) { Type::Default }
	multi method for-oid(16) { Type::Bool }
	multi method for-oid(17) { Type::Blob }
	multi method for-oid(Int $ where 20|21|23|26) { Type::Int }
	multi method for-oid(Int $ where 700|701) { Type::Num }
	multi method for-oid(1082) { Type::Date }
	multi method for-oid(Int $ where 1114|1184) { Type::DateTime }
	multi method for-oid(1700) { Type::Rat }
	multi method for-oid(1000) { Type::Array[Type::Bool, 1000] }
	multi method for-oid(1001) { Type::Array[Type::Blob, 1001] }
	multi method for-oid(Int $ where 1002|1003|1009|1014|1015) { Type::Array[Type::Default, 1009] }
	multi method for-oid(Int $ where 1005|1007|1016|1028) { Type::Array[Type::Int, 1016] }
	multi method for-oid(Int $ where 1021|1022) { Type::Array[Type::Num, 1022] }
	multi method for-oid(1182) { Type::Array[Type::Date, 1182] }
	multi method for-oid(Int $ where 1115|1185) { Type::Array[Type::DateTime, 1185] }
	multi method for-oid(1231) { Type::Array[Type::Rat, 1231] }
}

class ResultSet {
	has Str @.columns is required;
	has Any:U @.types is required;
	has Supply $.rows is required;

	method hash-rows() {
		$!rows.map(-> @row { hash @!columns Z=> @row });
	}

	class Source {
		my class Column {
			has Str:D $.name is required;
			has Format:D $.format is required;
			has Type $.type is required;
			method new(FieldDescription:D $field, TypeMap $typemap) {
				my $type = $typemap.for-oid($field.type);
				self.bless(:name($field.name), :format($field.format), :$type);
			}
		}
		my sub decode(Column $column, Blob $value) {
			$column.type.decode($column.format, $value).self;
		}
		has Column @.columns is required;
		has Supplier:D $!rows handles<done quit> = Supplier::Preserving.new;
		method new(TypeMap $typemap, FieldDescription @fields?) {
			my @columns = @fields.map: { Column.new($^field, $typemap) };
			self.bless(:@columns);
		}
		method add-row(@row) {
			$!rows.emit(eager @!columns Z[&decode] @row);
		}
		method resultset(ResultSet:U $resultset) {
			my @columns = @!columns».name;
			my @types   = @!columns».type;
			$resultset.new(:@columns, :@types, :rows($!rows.Supply));
		}
	}
}

my class Protocol::Query does Protocol {
	has TypeMap $.typemap is required;
	has ResultSet::Source $!source;
	has Supplier:D $.supplier handles(:finished<done>) is required;
	has ResultSet:U $.resultset is required;

	multi method incoming-message(Packet::RowDescription $ (:@fields)) {
		$!source = ResultSet::Source.new($!typemap, @fields);
		$!supplier.emit($!source.resultset(:$!resultset));
	}
	multi method incoming-message(Packet::DataRow $ (:@values)) {
		$!source.add-row(@values);
	}
	multi method incoming-message(Packet::EmptyQueryResponse $) {
		$!source = ResultSet::Source.new($!typemap);
		$!supplier.emit($!source.resultset(:$!resultset));
	}
	multi method incoming-message(Packet::CommandComplete $) {
		$!source.done with $!source;
		$!source = Nil;
	}
	method failed(%values) {
		$!supplier.quit('Query got error: ' ~ %values{Message});
	}
}

my enum Stage (:Parsing<parse>, :Binding<bind>, :Describing<describe>, :Executing<execute>, :Closing<close>, :Syncing<sync>);

my class Protocol::ExtendedQuery does Protocol {
	has Promise:D $.result is required;
	has TypeMap $.typemap is required;
	has ResultSet::Source $!source;
	has Stage:D $.stage = Parsing;
	has ResultSet:U $.resultset is required;
	multi method incoming-message(Packet::ParseComplete $) {
		$!stage = Binding;
	}
	multi method incoming-message(Packet::BindComplete $) {
		$!stage = Describing;
	}
	multi method incoming-message(Packet::RowDescription $ (:@fields)) {
		$!stage = Executing;
		$!source = ResultSet::Source.new($!typemap, @fields);
		$!result.keep($!source.resultset($!resultset));
	}
	multi method incoming-message(Packet::NoData $) {
		$!stage = Executing;
	}
	multi method incoming-message(Packet::DataRow $ (:@values)) {
		$!source.add-row(@values);
	}
	multi method incoming-message(Packet::EmptyQueryResponse $) {
		$!stage = Closing;
	}
	multi method incoming-message(Packet::CommandComplete $) {
		$!stage = Closing;
		if $!source {
			$!source.done;
			$!source = Nil;
		} elsif not $!result {
			$!result.keep;
		}
	}
	multi method incoming-message(Packet::CloseComplete $) {
		$!stage = Syncing;
	}
	method finish() {
		$!result.keep unless $!result;
	}
	method failed(%values) {
		my $exception = X::Server.new("Could not $!stage.value()", %values);
		if not $!result {
			$!result.break($exception);
		} elsif $!source {
			$!source.quit($exception);
		}
	}
}

class Client { ... }

class PreparedStatement {
	has Client:D $.client is required;
	has Str:D $.name is required;
	has Type @.types is required;
	has Bool $!closed = False;
	method resultset() { ResultSet }
	method execute(**@values, :@output-types) {
		die X::Client.new('Prepared statement already closed') if $!closed;
		die X::Client.new("Wrong number or arguments, got {+@values} expected {+@!types}") if @values != @!types;
		$!client.execute-prepared(self, @values, :@output-types, :resultset(self.resultset));
	}
	method close(--> Promise) {
		$!closed = True;
		$!client.close-prepared(self);
	}
	method DESTROY() {
		self.close unless $!closed;
	}
}

my class Protocol::Prepare does Protocol {
	has Client:D $.client is required;
	has Str:D $.name is required;
	has Promise:D $.result is required;
	has PreparedStatement:U $.prepared-statement is required;
	has Type @!types;

	multi method incoming-message(Packet::ParseComplete $) {
	}
	multi method incoming-message(Packet::RowDescription $ (:@fields)) {
	}
	multi method incoming-message(Packet::ParameterDescription $ (:@types)) {
		@!types = @types.map({ $!client.typemap.for-oid($^type) });
	}
	method finished() {
		$!result.keep($!prepared-statement.new(:$!name, :$!client, :@!types));
	}
	method failed(%values) {
		$!result.break(X::Server.new('Could not prepare', %values));
	}
}

my class Protocol::Close does Protocol {
	has Promise $.result is required;
	multi method incoming-message(Packet::CloseComplete $) {
	}
	method finished() {
		$!result.keep unless $!result;
	}
	method failed(%values) {
		$!result.break(X::Server.new('Could not close prepared statement', %values));
	}
}

class Notification {
	has Int:D $.sender is required;
	has Str:D $.channel is required;
	has Str:D $.payload is required;
}

class Client {
	has Protocol $!protocol;
	has Promise $!startup-promise = Promise.new;
	has Supplier $!outbound-messages handles(:outbound-messages<Supply>) = Supplier.new;
	has Supply $!outbound-data;
	has Supplier $!notifications handles(:notifications<Supply>) = Supplier.new;
	has PacketDecoder $!decoder = PacketDecoder.new;
	has Int $!prepare-counter = 0;
	has TypeMap $.typemap = TypeMap::Simple;

	has Int $!process-id handles(:process-id<self>);
	has Int $!secret-key;
	has Str %!parameters handles(:get-parameter<AT-KEY>);

	my class Task {
		has Protocol:D $.protocol is required;
		has Packet::Base:D @.packets is required;
	}
	has Task @!tasks;

	method !send($packet) {
		$!outbound-messages.emit($packet);
	}

	method !send-next($protocol, @packets) {
		$!protocol = $protocol;
		for @packets -> $packet {
			self!send($packet);
		}
	}

	method !handle-next() {
		with @!tasks.shift -> (:$protocol, :@packets) {
			self!send-next($protocol, @packets);
		} else {
			$!protocol = Nil;
		}
	}

	method !submit(Protocol:D $protocol, @packets) {
		if $!protocol or not $!startup-promise {
			@!tasks.push(Task.new(:$protocol, :@packets));
		} else {
			self!send-next($protocol, @packets);
		}
	}

	method outbound-data() {
		$!outbound-data //= $!outbound-messages.Supply.map(*.encode);
	}
	method incoming-data(Blob:D $data --> Nil) {
		$!decoder.add-data($data);
		while $!decoder.read-packet -> $packet {
			self.incoming-message($packet);
		}
	}

	multi method incoming-message(Packet::AuthenticationOk $) {
	}
	multi method incoming-message(Packet::NegotiateProtocolVersion $ (:$newest-minor-version)) {
		$!startup-promise.break(X::Client.new('Unsupported protocol version ' ~ $newest-minor-version));
	}
	multi method incoming-message(Packet::BackendKeyData $ (:$process-id, :$secret-key)) {
		$!process-id = $process-id;
		$!secret-key = $secret-key;
	}
	multi method incoming-message(Packet::ParameterStatus $ (:$name, :$value)) {
		%!parameters{$name} = $value;
	}
	multi method incoming-message(Packet::NotificationResponse $packet (:$sender, :$channel, :$payload)) {
		$!notifications.emit(Notification.new(:$sender, :$channel, :$payload));
	}
	multi method incoming-message(Packet::ErrorResponse $ (:%values)) {
		$!protocol.failed(%values);
	}
	multi method incoming-message(Packet::ReadyForQuery $) {
		$!protocol.finished;
		self!handle-next;
	}
	multi method incoming-message(Packet::Base $packet) {
		$!protocol.incoming-message($packet) with $!protocol;
	}

	method startTls(--> Blob) {
		OpenPacket::SSLRequest.new.encode;
	}

	method startup(Str:D $user!, Str $database, Str $password --> Promise) {
		die X::Client.new('Already started') if $!startup-promise or $!protocol;
		my $authenticator = $password.defined ?? Authenticator::Password.new(:$user, :$password) !! Authenticator::Null.new;
		my %parameters = :$user;
		%parameters<database> = $database with $database;
		my &send-message = { self!send($^message) };
		$!protocol = Protocol::Authenticating.new(:client(self), :$authenticator, :$!startup-promise, :&send-message);
		self!send(OpenPacket::StartupMessage.new(:%parameters));
		$!startup-promise;
	}

	method query-multiple(Str $query, ResultSet:U :$resultset --> Supply) {
		my $supplier = Supplier::Preserving.new;
		self!submit(Protocol::Query.new(:$supplier, :$resultset), [ Packet::Query.new(:$query) ]);
		$supplier.Supply;
	}

	sub compress-formats(@formats) {
		if all(@formats) === Text {
			();
		} elsif all(@formats) === Binary {
			(Binary);
		} else {
			@formats;
		}
	}

	sub compress-oids(@oids) {
		all(@oids) == 0 ?? () !! @oids;
	}

	method query(Str $query, **@values, :@output-types, ResultSet:U :$resultset --> Promise) {
		my $result = Promise.new;
		my $protocol = Protocol::ExtendedQuery.new(:$result, :$!typemap, :$resultset);

		my @types = @values.map: { $!typemap.for-type($^value) };
		my @oids = compress-oids(@types».oid);
		my @formats = compress-formats(@types».format);
		my @fields = @types Z[&type-encode] @values;

		my @outputs = @output-types.map: { $!typemap.for-type($^value) };
		my @result-formats = compress-formats(@outputs».format);

		self!submit($protocol, [
			Packet::Parse.new(:$query, :@oids), Packet::Bind.new(:@formats, :@fields),
			Packet::Describe.new, Packet::Execute.new, Packet::Close.new(:type(Prepared)), Packet::Sync.new,
		]);
		$result;
	}

	method prepare(Str $query, Str :$name = "prepared-{++$!prepare-counter}", :@input-types, PreparedStatement:U :$prepared-statement --> Promise) {
		my $result = Promise.new;
		my @types = @input-types.map: { $!typemap.for-type($^value) };
		my @oids = compress-oids(@types».oid);
		my $protocol = Protocol::Prepare.new(:client(self), :$name, :$result, :$prepared-statement);
		self!submit($protocol, [
			Packet::Parse.new(:$query, :$name, :@oids), Packet::Describe.new(:$name, :type(Prepared)), Packet::Sync.new,
		]);
		$result;
	}

	method execute-prepared(PreparedStatement $prepared, @values, :@output-types --> Promise) {
		my $result = Promise.new;
		my $protocol = Protocol::ExtendedQuery.new(:$result, :$!typemap, :stage(Binding), :resultset($prepared.resultset));

		my @types = $prepared.types;
		my @formats = compress-formats(@types».format);
		my @fields = @types Z[&type-encode] @values;

		my @outputs = @output-types.map: { $!typemap.for-type($^value) };
		my @result-formats = compress-formats(@outputs».format);

		self!submit($protocol, [
			Packet::Bind.new(:name($prepared.name), :@formats, :@fields, :@result-formats),
			Packet::Describe.new, Packet::Execute.new, Packet::Close.new(:type(Portal)), Packet::Sync.new
		]);
		$result;
	}

	method close-prepared(PreparedStatement $prepared) {
		my $result = Promise.new;
		my $protocol = Protocol::Close.new(:$result);
		self!submit($protocol, [ Packet::Close.new(:name($prepared.name), :type(Prepared)), Packet::Sync.new ]);
		$result;
	}

	method terminate(--> Nil) {
		self!send(Packet::Terminate.new);
		$!outbound-messages.done;
	}
}

=begin pod

=head1 Name

Protocol::Postgres - a sans-io postgresql client

=head1 Synopsis

=begin code :lang<raku>

use v6.d;
use Protocol::Postgres;

my $socket = await IO::Socket::Async.connect($host, $port);
my $client = Protocol::Postgres::Client.new;
$socket.Supply(:bin).act({ $client.incoming-data($^data) });
$client.outbound-data.act({ $socket.write($^data) });

await $client.startup($user, $database, $password);

my $resultset = await $client.query('SELECT * FROM foo WHERE id = $1', 42);
react {
	whenever $resultset.hash-rows -> (:$name, :$description) {
		say "$name is $description";
	}
}

=end code

=head1 Description

Protocol::Postgres is sans-io implementation of (the client side of) the postgresql protocol. It is typically used through the C<Protocol::Postgres::Client> class.

=head1 Client

C<Protocol::Postgres::Client> has the following methods

=head2 new(--> Protocol::Postgres::Client)

This creates a new postgres client. It supports one optional named argument:

=begin item1
TypeMap :$typemap = TypeMap::Simple

This is the typemap that is used to translate between Raku's and Postgres' typesystem. The default mapping supports common built-in types such as strings, numbers, bools, dates, datetimes and blobs.
=end item1

=head2 outgoing-data(--> Supply)

This returns a C<Supply> of C<Blob>s to be written to the server.

=head2 incoming-data(Blob --> Nil)

This consumes bytes received from the server.

=head2 startup($user, $database?, $password? --> Promise)

This starts the handshake to the server. C<$database> may be left undefined, the server will use C<$user> as database name. If a C<$password> is defined, any of clearnext, md5 or SCRAM-SHA-256 based authentication is supported.

The resulting promise will finish when the connection is ready for queries.

=head2 query($query, @bind-values --> Promise)

This will issue a query with the given bind values, and return a promise to the result.

For fetching queries such as C<SELECT> the result will be a C<ResultSet> object, for manipulation (e.g. C<INSERT>) and definition (e.g. C<CREATE>) queries it will result in the value C<True>.

Both the input types and the output types will be typemapped between Raku types and Postgres types using the typemapper.

=head2 query-multiple($query --> Supply[ResultSet])

This will issue a complex query that may contain multiple statements, but can not use bind values. It will return a C<Supply> to the results of each query.

=head2 prepare($query --> Promise[PreparedStatement])

This prepares the query, and returns a Promise to the PreparedStatement object.

=head2 startTls(--> Blob)

This will return the marker that should be written to the server to start upgrading the connection to use TLS. If the server responds with a single C<S> byte the proposal is accepted and the client is expected to initiate the TLS handshake. If the server responds with an C<N> it is rejected, and the connection proceeds in cleartext.

=head2 terminate(--> Nil)

This sends a message to the server to terminate the connection

=head2 notifications(--> Supply[Notification])

This returns a supply with all notifications that the current connection is subscribed to. Channels can be subscribed using the C<LISTEN> command, and messages can be sent using the C<NOTIFY> command.

=head2 process-id(--> Int)

This returns the process id of the backend of this connection. This is useful for debugging purposes and for notifications.

=head2 get-parameter(Str $name --> Str)

This returns various parameters, currently known parameters are: C<server_version>, C<server_encoding>, C<client_encoding>, C<application_name>, C<default_transaction_read_only>, C<in_hot_standby>, C<is_superuser>, C<session_authorization>, C<DateStyle>, C<IntervalStyle>, C<TimeZone>, C<integer_datetimes>, and C<standard_conforming_strings>.

=head1 ResultSet

A C<Protocol::Postgres::ResultSet> represents the results of a query, if any.

=head2 columns(--> List)

This returns the column names for this resultset.

=head2 rows(--> Supply[List])

This returns a Supply of rows. Each row is a list of values.

=head2 hash-rows(--> Supply[Hash])

This returns a Supply of rows. Each row is a hash with the column names as keys and the row values as values.

=head1 PreparedStatement

A C<Protocol::Postgres::PreparedStatement> represents a prepated statement. Its reason of existence is to call C<execute> on it.

=head2 execute(@arguments --> Promise[ResultSet])

This runs the prepared statement, much like the C<query> method would have done.

=head2 close()

This closes the prepared statement.

=head1 Notification

C<Protocol::Postgres::Notification> has the following methods:

=head2 sender(--> Int)

This is the process-id of the sender

=head2 channel(--> Str)

This is the name of the channel that the notification was sent on

=head2 payload(--> Str)

This is the payload of the notification

=head1 Todo

=item1 Implement the copy protocol

=head1 Author

Leon Timmermans <fawaka@gmail.com>

=head1 Copyright and License

Copyright 2022 Leon Timmermans

This library is free software; you can redistribute it and/or modify it under the Artistic License 2.0.

=end pod
