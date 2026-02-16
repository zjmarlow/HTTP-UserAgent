unit class HTTP::Header;

use HTTP::Header::Field;
use HTTP::Header::ETag;

my constant $CRLF = "\x[0D]\x[0A]";

has Bool $.strict is rw;
# headers container
has @.fields;

grammar Grammar::Strict {
    token TOP {
        <message-header>
    }
    token message-header {
        [ <[\t\x[20]]>* <field> <[\t\x[20]]>* \x[0d]\x[0a] ]*
    }
    #| includes any VCHAR except delimiters
    #| https://datatracker.ietf.org/doc/html/rfc9110#name-tokens
    token token {
        <[!#$%&'*+\-.^_`|~0..9a..zA..Z]>+
    }
    token field {
        | <etag>
        | <other-field>
    }
    token other-field {
        $<field-name>=<token> ':' \s* [ <value> | <quoted-string> ]
    }
    token etag {
        $<field-name>=[<[eE]><[tT]><[aA]><[gG]>] ':'\s* $<field-value>=[ [(W)'/']? <opaque-tag> ]
    }
    token opaque-tag {
        \" <opaque-content> \"
    }
    # visible chars except double quote
    token opaque-content {
        <[\x[21]..\x[FF]]-[\x[22]\x[7F]]>*
    }
    token vchars { <[\x[21]..\x[7E]]>+ } # visible ascii
    token field-vchars { <[\x[21]..\x[FF]]-[\x[7F]]>+ } # visible chars
    token value {
        <field-vchars> [ <[\t\x[20]]>* <field-vchars> ]*
    }
    token quoted-string {
        \" <quoted-content> \"
    }
    token quoted-content {
        [<qtd-text> | <quoted-pair>]*
    }
    # visible chars plus tab, space, except double quotes and backslash
    token qtd-text {
        <[\t\x[20]..\x[FF]]-[\x[22]\x[5C]\x[7F]]>+
    }
    # visible chars plus tab, space
    token quotable-char {
        <[\t\x[20]..\x[FF]]-[\x[7F]]>
    }
    token quoted-pair {
        \\ <quotable-char>
    }
}

class Actions::Strict {
    method etag ( $/ ) {
        $*OBJ.field:
                HTTP::Header::ETag.new:
                        $<opaque-tag>.made,
                        weak => $/[0].Bool
    }
    method other-field ( $/ ) {
        my $k = $<field-name>.Str;
        my @v = $<quoted-string>
                ?? $<quoted-string>.made
                !! map *.trim, $<value>.Str.split: ',';
        if $*OBJ.field: $<field-name> {
            $*OBJ.push-field: |( $k => @v );
        } else {
            $*OBJ.field: |( $k => @v );
        }
    }
    method opaque-tag ( $/ ) {
        make $<opaque-content>.Str;
    }
    method quoted-string ( $/ ) {
        make $<quoted-content>.Str;
    }
}

our grammar HTTP::Header::Grammar {
    token TOP {
        [ <message-header> \r?\n ]*
    }

    token message-header {
        $<field-name>=[ <-[:]>+ ] ':' <field-value>
    }

    token field-value {
        [ <!before \h> ( ['W/' | 'w/'] )? <quot>?
            $<field-content>=[ <-[\r\n"]>+ ]  || \h+ ]*
        <quot>?
    }
    token quot {
        <['"]>
    }
}

our class HTTP::Header::Actions {
    method message-header($/) {
      my $value = $<field-value>.made;
      my $k = ~$<field-name>;
      my @v = $value<content>.Array;

      @v[0] = $value<prefix> ~ @v[0] if $value<prefix> && $k.lc ne 'etag';
      if $k && @v -> $v {
        if $*OBJ.field($k) {
          $*OBJ.push-field: |($k => $v);
        } else {
          $*OBJ.field: |($k => $v);
        }
      }
    }

    method field-value($/) {
        make {
          prefix => $0,
          content => $<field-content> ??
            $<field-content>.Str.split(',')>>.trim !! Nil
        }
    }
}

# we want to pass arguments like this: .new(a => 1, b => 2 ...)
method new(Bool $strict = False, *%fields) {
    my @fields = %fields.sort(*.key).map: {
        HTTP::Header::Field.new(:name(.key), :values(.value.list));
    }

    self.bless(:$strict, :@fields)
}

proto method field(|) {*}

# set fields
multi method field(*%fields) {
    for %fields.sort(*.key) -> (:key($k), :value($v)) {
        my $f = HTTP::Header::Field.new(:name($k), :values($v.list));
        if @.fields.first({ .name.lc eq $k.lc }) {
            @.fields[@.fields.first({ .name.lc eq $k.lc }, :k)] = $f;
        }
        else {
            @.fields.push: $f;
        }
    }
}

# get fields
multi method field($field) {
    my $field-lc := $field.lc;
    @.fields.first(*.name.lc eq $field-lc)
}

multi method field ( HTTP::Header::ETag:D $etag ) {
    @.fields.push: $etag;
}


# initialize fields
method init-field(*%fields) {
    for %fields.sort(*.key) -> (:key($k), :value($v)) {
        my $k-lc := $k.lc;
        @.fields.push:
          HTTP::Header::Field.new(:name($k), :values($v.list))
          unless @.fields.first(*.name.lc eq $k-lc);
    }
}

# add value to existing fields
method push-field(*%fields) {
    for %fields.sort(*.key) -> (:key($k), :value($v)) {
        my $k-lc := $k.lc;
        @.fields.first(*.name.lc eq $k-lc).values.append: $v.list;
    }
}

# remove a field
method remove-field(Str $field) {
    my $field-lc := $field.lc;
    @.fields.splice($_, 1)
      with @.fields.first(*.name.lc eq $field-lc, :k);
}

# get fields names
method header-field-names() {
    @.fields.map(*.name)
}

# return the headers as name -> value hash
method hash(--> Hash:D) {
    @.fields.map({ $_.name => $_.values }).Hash
}

# remove all fields
method clear() {
    @.fields = ();
}

# get header as string
method Str($eol is copy = "\n", Bool :$strict is copy) {
    $strict ||= $!strict;
    $eol = $CRLF if $strict;
    @.fields.map({ "$_.name(): {self.field($_.name)}$eol" }).join
}

method parse($raw, Bool :$strict is copy) {
    $strict ||= $!strict;
    if $strict {
        my $*OBJ = self;
        Grammar::Strict.parse: $raw, actions => Actions::Strict;
    } else {
        my $*OBJ = self;
        HTTP::Header::Grammar.parse($raw, :actions(HTTP::Header::Actions));
    }
}

# vim: expandtab shiftwidth=4
