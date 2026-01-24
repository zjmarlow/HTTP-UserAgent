use HTTP::Header::Field;

unit class HTTP::Header::ETag is HTTP::Header::Field;

has Bool:D $.weak is required;

method new ( $value, Bool :$weak ) {
	self.bless:
			name => 'ETag',
			:$weak,
			values => $value
}
