unit class HTTP::Message;

use HTTP::Header;
use HTTP::MediaType;
use Encode;

has Bool $.strict is rw;
has HTTP::Header $.header = HTTP::Header.new;
has $.content is rw;

has $.protocol is rw = 'HTTP/1.1';

has Bool $.binary = False;
has Str  @.text-types;

my constant $CRLF = "\x[0d]\x[0a]";
my constant $DELIM = $CRLF x 2;
my constant $STRICT = True; # prepare for assoc. strict to positional strict

multi method new($content, Bool $strict = False, *%fields) {
    my $header = HTTP::Header.new($strict, |%fields);

    self.bless(:$header, :$content, :$strict);
}

multi method new(Bool $strict = False, *%fields) is default {
    my $header = HTTP::Header.new($strict, |%fields);

    self.bless(:$header, :$strict);
}

method add-content($content) {
    $.content ~= $content;
}

class X::Decoding is Exception {
    has HTTP::Message $.response;
    has Blob $.content;
    method message() {
        "Problem decoding content";
    }
}

method content-type(--> Str:D) {
    $!header.field('Content-Type').values[0] || '';
}

has HTTP::MediaType $!media-type;

method media-type(--> HTTP::MediaType) {
    without $!media-type { 
        if self.content-type() -> $ct {
            $!media-type = HTTP::MediaType.parse($ct);
        }
    }
    $!media-type
}

# Don't want to put the heuristic in the HTTP::MediaType
# Also moving this here makes it much more easy to test

method charset(--> Str:D) {
    if self.media-type -> $mt {
        $mt.charset || ( $mt.major-type eq 'text' ?? $mt.sub-type eq 'html' ?? 'utf-8' !! 'iso-8859-1' !! 'utf-8');
    }
    else {
        # At this point we're probably screwed anyway
        'iso-8859-1'
    }
}

# This is already a candidate for refactoring
# Just want to get it working
method is-text(--> Bool:D) {
    if $!binary {
        False
    }
    elsif self.media-type -> $mt {
        if $mt.type ~~ any(@!text-types) {
            True
        }
        else {
            given $mt.major-type {
                when 'text' {
                    True
                }
                when any(<image audio video>) {
                    False
                }
                when 'application' {
                    given $mt.sub-type {
                        when /xml|javascript|json/ {
                            True
                        }
                        default {
                            False
                        }
                    }
                }
                default {
                    # Not sure about this
                    True
                }
            }
        }
    }
    else {
        # No content type, try and blow up
        True
    }
}

method is-binary(--> Bool:D) { !self.is-text }

#| multiple transfer-codings can be listed; chunked should be last
#| https://datatracker.ietf.org/doc/html/rfc2616#section-14.41
#| https://datatracker.ietf.org/doc/html/rfc7230#section-4
multi method is-chunked ( HTTP::Header $header --> Bool:D ) {
    my $enc = $header.field('Transfer-Encoding');
    so $enc and $enc.values.tail.trim.lc.ends-with: 'chunked'
}
multi method is-chunked(--> Bool:D) {
    self.is-chunked: $!header;
}

method content-encoding() {
    $!header.field('Content-Encoding');
}

class X::Deflate is Exception {
    has Str $.message;
}

method inflate-content(--> Blob:D) {
    if self.content-encoding -> $v is copy {
        # This is a guess
        $v = 'zlib' if $v eq 'compress' ;
        $v = 'zlib' if $v eq 'deflate';
        try require ::('Compress::Zlib');
        if ::('Compress::Zlib::Stream') ~~ Failure {
            X::Deflate.new(message => "Please install 'Compress::Zlib' to uncompress '$v' encoded content").throw;
        }
        else {
            my $z = ::('Compress::Zlib::Stream').new( |{ $v => True });
            $z.inflate($!content);
        }
    }
    else {
        $!content;
    }
}

method decoded-content(:$bin) {
    return $!content if $!content ~~ Str || $!content.bytes == 0;

    my $content = self.inflate-content;
    # [todo]
    # If charset is missing from Content-Type, then before defaulting
    # to anything it should attempt to extract it from $.content like (for HTML):
    # <meta charset="UTF-8"> 
    # <meta http-equiv="content-type" content="text/html; charset=UTF-8">
    
    my $decoded_content;

    if !$bin && self.is-text {
        my $charset = self.charset;
        $decoded_content = try {
            Encode::decode($charset, $content);
        } || try {
            $content.decode('iso-8859-1');
        } || try { 
            $content.unpack("A*") 
        } || X::Decoding.new(content => $content, response => self).throw;
    }
    else {
        $decoded_content = $content;
    }

    $decoded_content
}

multi method field(Str $f) {
    $.header.field($f)
}

multi method field(*%fields) {
    $.header.field(|%fields)
}

method push-field(*%fields) {
    $.header.push-field(|%fields)
}

method remove-field(Str $field) {
    $.header.remove-field($field)
}

method clear {
    $.header.clear;
    $.content = ''
}

# parsing content with embedded CRLFs NYI
#   it would require taking encoding into account and working with Blobs
method !parse-content-strict ( $content ) {
    if self.is-chunked {
        # technically incorrect - content allowed to contain embedded CRLFs
        my @lines = $content.split: $CRLF;
        # pop zero-length Str that occurs after last chunk
        #   what to do if this doesn't happen?
        @lines.pop if @lines %2;
        @lines = grep so *,
                    @lines.map:
                            -> $d, $s { $d ~~ /^<[0..9]>/ ?? $s !! Str }
                ;
        $.content = @lines.join;
    } else {
        $.content = $content;
    }
}

method !parse-first ($raw_message, --> Str) {
    my ( $start-line, $rest ) = $raw_message.split: $CRLF, 2;
    my ($first, $second, $third) = $start-line.split(/\s+/);
    if $third.index('/') { # is a request
        $.protocol = $third;
    }
    else {               # is a response
        $.protocol = $first;
    }
    $rest;
}

method !parse-header($header) {
    my @lines = $header.split($CRLF);
    for @lines -> $line {
        my ($k, $v) = $line.split(/\:\s*/, 2);
        if $k and $v {
            if $!header.field($k) {
                $!header.push-field: |($k => $v.split(',')>>.trim);
            } else {
                $!header.field: |($k => $v.split(',')>>.trim);
            }
        }
        # else warn?
    }
}

method !parse-header-strict($header) {
    $!header.parse($header, $STRICT);
}

method parse($raw_message, Bool $strict is copy = False) {
    $strict ||= $!strict;
    my $rest = self!parse-first($raw_message);
    my ($header, $content) = $rest.split($DELIM, 2);
    if $strict {
        $!header.parse($header, $STRICT);
        self!parse-content-strict($content) if $content;
    } else {
        self!parse-header($header);
        $!content = join "\n", grep so *, $content.split: $CRLF;
    }
    self
}

multi method Str(Str $eol is copy = "\n", Bool $strict is copy = False, :$debug, Bool :$bin) {
    $strict ||= $!strict;
    $eol = $CRLF if $strict;
    
    my constant $max_size = 300;
    self.field: Content-Length => ( $!content.?encode or $!content ).bytes.Str
        if $strict and $!content and not self.is-chunked;
    my $s = $.header.Str($eol, $strict);
    $s ~= $eol if $!content and not $strict;
    
    # The :bin will be passed from the H::UA
    if not $bin {
        if $strict {
            $s ~= $CRLF ~ ( $.content || '' );
        } else {
            $s ~=  $.content ~ $eol if $.content and !$debug;
        }
    }
    if $.content and $debug {
        if $bin || self.is-binary {
            $s ~= $eol ~ "=Content size : " ~ $.content.elems ~ " bytes ";
            $s ~= "$eol ** Not showing binary content ** $eol";
        }
        else {
            $s ~= $eol ~ "=Content size: "~$.content.Str.chars~" chars";
            $s ~= "- Displaying only $max_size" if $.content.Str.chars > $max_size;
            $s ~= $eol ~ $.content.Str.substr(0, $max_size) ~ $eol;
        }
    }

    $s
}
multi method Str(Bool $strict is copy = False, :$debug, Bool :$bin) {
    self.Str: "\n", $strict, :$debug, :$bin;
}

# vim: expandtab shiftwidth=4
