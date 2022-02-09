unit module Protocol::Postgres:ver<0.0.1>:auth<cpan:LEONT>;

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

	method read-int32() {
		my $result = $!buffer.read-int32($!pos, BigEndian);
		$!pos += 4;
		$result;
	}
	method read-int16() {
		my $result = $!buffer.read-int16($!pos, BigEndian);
		$!pos += 2;
		$result;
	}
	method read-int8() {
		my $result = $!buffer.read-int8($!pos++);
		$result;
	}
	method peek-int8() {
		$!buffer.read-uint8($!pos);
	}
	method read-string() {
		my $end = $!pos;
		$end++ while $!buffer[$end] != 0;
		my $result = $!buffer.subbuf($!pos, $end - $!pos);
		$!pos = $end + 1;
		$result.decode;
	}
	method read-buffer(Int $length) {
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

enum Format <Text Binary>;
multi map-type(Format) { Enum[Format, Int16] }

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

class OpenPacket::CancelRequest does OpenPacket::Base {
	method !schema() { state $ = Schema.new((:80877102id, :process-id(Int), :secret-key(Int))) }
	has Int:D $.process-id is required;
	has Int:D $.secret-key is required;
}

enum RequestType (:Prepared(83), :Portal(80));
multi map-type(RequestType) { Enum[RequestType, Int8] }

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

enum ErrorField (:SeverityLocalized(83), :Severity(86), :ErrorCode(67), :Message(77), :Detail(68), :Hint(72), :Position(80), :InternalPosition(112), :InternalQuery(113), :Where(87), :SchemaName(115), :Table(116), :Column(99), :Datatype(100), :Constraint(110), :File(70), :Line(76), :Routine(82));
multi map-type(ErrorField) { Enum[ErrorField, Int8] }

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

class OpenPacket::GSSENCRequest does OpenPacket::Base {
	method !schema() { state $ = Schema.new((:80877104id)) }
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

enum QueryStatus (:Idle(73), :Transaction(84), :Error(69));
multi map-type(QueryStatus) { Enum[QueryStatus, Int8] }

class Packet::ReadyForQuery does Packet::Base {
	method header(--> 90) {}
	method !schema() { state $ = Schema.new((:status(QueryStatus))) }
	has QueryStatus:D $.status is required;
}

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

class OpenPacket::SSLRequest does OpenPacket::Base {
	method !schema() { state $ = Schema.new((:80877103id)) }
}

class OpenPacket::StartupMessage does OpenPacket::Base {
	method !schema() { state $ = Schema.new((:196608id, :parameters(Hash[Str, Str]))) }
	has Str %.parameters is required;
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
		my &decoder = %!decoder-for{$payload[0]} or die 'Invalid message type ' ~ $payload.subbuf(0, 1).decode;
		decoder(Blob.new($payload));
	}
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
		$startup-promise.break('Can not authenticate');
		self;
	}
}

class Authenticator::Null does Authenticator {
}

my class Authenticator::SCRAM does Authenticator {
	has $.scram is required;
	multi method incoming-message(Packet::AuthenticationSASLContinue $ (:$server-payload), Promise $startup-promise, &send-message) {
		try {
			my $client-payload = $!scram.final-message($server-payload.decode).encode;
			CATCH { default {
				$startup-promise.break("Invalid server message: {.message}", )
			}}
			send-message(Packet::SASLResponse.new(:$client-payload));
		}
		self;
	}
	multi method incoming-message(Packet::AuthenticationSASLFinal $ (:$server-payload), Promise $startup-promise, &send-message) {
		if not try $!scram.validate($server-payload.decode) {
			my $reason = 'Could not validate final server message: ' ~ ($! // 'did not verify');
			$startup-promise.break($reason);
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
			$startup-promise.break('Could not load MD5 module');
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
				$startup-promise.break('Could not load SCRAM module');
			}
		} else {
			$startup-promise.break("Client does not support SASL mechanisms: @mechanisms[]");
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
	method failed(%values) { $!startup-promise.break('Could not authenticate: ' ~ %values{Message}) }
}

multi encode-string(Str:D $str) {$str.encode }
multi encode-string(Str:U $str) { Blob }
multi decode-string(Blob:D $buf) { $buf.decode }
multi decode-string(Blob:U $buf) { Str }

role FieldEncoding {
	method formats() { ... }
	method encode(@values) { ... }
	method decode(@values) { ... }
}

class FieldEncoding::AllText does FieldEncoding {
	method formats() { () }
	method encode(@values) {
		@values.map(&encode-string);
	}
	method decode(@values) {
		@values.map(&decode-string);
	}
}

class FieldEncoding::AllBinary does FieldEncoding  {
	method formats() { (Binary) }
	method encode(@values) {
		@values;
	}
	method decode(@values) {
		@values;
	}
}

class FieldEncoding::Variant does FieldEncoding {
	has Format @.formats;
	method encode(@values) {
		(@!formats Z @values).map: -> ($format, $value) {
			$format === Text ?? encode-string($value) !! $value;
		}
	}
	method decode(@values) {
		(@!formats Z @values).map: -> ($format, $value) {
			$format === Text ?? decode-string($value) !! $value;
		}
	}
}

class ResultSet {
	has Str @.columns is required;
	has Supply $.rows is required;

	method hash-rows() {
		$!rows.map(-> @row { hash @!columns Z=> @row });
	}

	class Source {
		has FieldEncoding $.encoder is required;
		has Str @.columns is required;
		has Supplier:D $!rows handles<done> = Supplier::Preserving.new;
		multi fieldencoding-for(Format @formats) {
			if @formats eqv Array[Format].new|Array[Format].new(Text) {
				FieldEncoding::AllText;
			} elsif @formats eqv Array[Format].new(Binary) {
				FieldEncoding::AllBinary;
			} else {
				FieldEncoding::Variant.new(:@formats);
			}
		}
		method new(FieldDescription @fields?) {
			my Format @formats = @fields».format;
			my $encoder = fieldencoding-for(@formats);
			my @columns = @fields».name;
			self.bless(:$encoder, :@columns);
		}
		method add-row(@row) {
			$!rows.emit($!encoder.decode(@row).eager);
		}
		method resultset() {
			ResultSet.new(:@!columns, :rows($!rows.Supply));
		}
	}
}

my class Protocol::Query does Protocol {
	has ResultSet::Source $!source;
	has Supplier:D $.supplier handles(:finished<done>) is required;

	multi method incoming-message(Packet::RowDescription $ (:@fields)) {
		$!source = ResultSet::Source.new(@fields);
		$!supplier.emit($!source.resultset);
	}
	multi method incoming-message(Packet::DataRow $ (:@values)) {
		$!source.add-row(@values);
	}
	multi method incoming-message(Packet::EmptyQueryResponse $) {
		$!source = ResultSet::Source.new;
		$!supplier.emit($!source.resultset);
	}
	multi method incoming-message(Packet::CommandComplete $) {
		$!source.done with $!source;
		$!source = Nil;
	}
	method failed(%values) {
		$!supplier.quit('Query got error: ' ~ %values{Message});
	}
}

my class Protocol::ExtendedQuery does Protocol {
	has Promise:D $.result is required;
	has ResultSet::Source $!source;
	my enum Stage (:Parsing<parse>, :Binding<bind>, :Describing<describe>, :Executing<execute>, :Closing<close>, :Syncing<sync>);
	has Stage $!stage = Parsing;
	multi method incoming-message(Packet::ParseComplete $) {
		$!stage = Binding;
	}
	multi method incoming-message(Packet::BindComplete $) {
		$!stage = Describing;
	}
	multi method incoming-message(Packet::RowDescription $ (:@fields)) {
		$!stage = Executing;
		$!source = ResultSet::Source.new(@fields);
		$!result.keep($!source.resultset);
	}
	multi method incoming-message(Packet::NoData $) {
		$!stage = Executing;
		$!source = ResultSet::Source.new;
		$!result.keep($!source.resultset);
	}
	multi method incoming-message(Packet::DataRow $ (:@values)) {
		$!source.add-row(@values);
	}
	multi method incoming-message(Packet::EmptyQueryResponse $) {
		$!stage = Closing;
		$!source.done;
		$!source = Nil;
	}
	multi method incoming-message(Packet::CommandComplete $) {
		$!stage = Closing;
		$!source.done;
		$!source = Nil;
	}
	multi method incoming-message(Packet::CloseComplete $) {
		$!stage = Syncing;
	}
	method failed(%values) {
		$!source.done with $!source;
		$!result.break("Could not $!stage.value(): %values{Message}");
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
		$!startup-promise.break('Unsupported protocol version ' ~ $newest-minor-version);
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
		die 'Already started' if $!startup-promise or $!protocol;
		my $authenticator = $password.defined ?? Authenticator::Password.new(:$user, :$password) !! Authenticator::Null.new;
		my %parameters = :$user;
		%parameters<database> = $database with $database;
		my &send-message = { self!send($^message) };
		$!protocol = Protocol::Authenticating.new(:client(self), :$authenticator, :$!startup-promise, :&send-message);
		self!send(OpenPacket::StartupMessage.new(:%parameters));
		$!startup-promise;
	}

	method query-multiple(Str $query --> Supply) {
		my $supplier = Supplier::Preserving.new;
		self!submit(Protocol::Query.new(:$supplier), [ Packet::Query.new(:$query) ]);
		$supplier.Supply;
	}

	sub fieldencoding-for-values(@values) {
		if all(@values) ~~ Str {
			FieldEncoding::AllText;
		} elsif all(@values) ~~ Blob {
			FieldEncoding::AllBinary;
		} else {
			my @formats = @values.map({ $^value ~~ Blob ?? Binary !! Text });
			FieldEncoding::Variant.new(:@formats);
		}
	}

	method query(Str $query, *@values --> Promise) {
		my $result = Promise.new;
		my $protocol = Protocol::ExtendedQuery.new(:$result);
		my $encoding = fieldencoding-for-values(@values);
		self!submit($protocol, [
			Packet::Parse.new(:$query),
			Packet::Bind.new(:formats($encoding.formats), :fields($encoding.encode(@values))),
			Packet::Describe.new, Packet::Execute.new, Packet::Close.new(:type(Prepared)), Packet::Sync.new,
		]);
		$result;
	}

	method terminate(--> Nil) {
		self!send(Packet::Terminate.new);
		$!outbound-messages.done;
	}
}

=begin pod

=head1 NAME

Protocol::Postgres - a sans-io postgresql client

=head1 SYNOPSIS

=begin code :lang<raku>

use Protocol::Postgres;

my $socket = await IO::Socket::Async.connect($host, $port);
my $client = Protocol::Postgres::Client.new;

react {
	whenever $client.startup($user, $database, $password) {
		# Start some queries
	}
	whenever $client.outbound-data {
		$socket.write($^packet);
	}
	whenever $socket.Supply(:bin) -> $data {
		$client.incoming-data($data);
		LAST done;
	}
}

=end code

=head1 DESCRIPTION

Protocol::Postgres is sans-io implementation of the (client side of) the postgresql protocol.

=head1 AUTHOR

Leon Timmermans <fawaka@gmail.com>

=head1 COPYRIGHT AND LICENSE

Copyright 2022 Leon Timmermans

This library is free software; you can redistribute it and/or modify it under the Artistic License 2.0.

=end pod
