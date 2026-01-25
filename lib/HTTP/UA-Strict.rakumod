use URI;

use HTTP::UserAgent;
use HTTP::Message;
use HTTP::Request;
use HTTP::Response;
use HTTP::Header;

class HTTP::Header-Strict is HTTP::Header {
    use HTTP::Header::ETag;
    
    grammar HTTP::Header-Strict::Grammar {
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
        token opaque-content {
            <[\x[21]..\x[FF]]-[\x[22]\x[7F]]>*
        }
        token vchars { <[\x[21]..\x[7E]]>+ }
        token field-vchars { <[\x[21]..\x[FF]]-[\x[7F]]>+ }
        token value {
            <field-vchars> [ <[\t\x[20]]>* <field-vchars> ]*
        }
        token quoted-string {
            \" <quoted-content> \"
        }
        token quoted-content {
            [<qtd-text> | <quoted-pair>]*
        }
        token qtd-text {
            <[\t\x[20]..\x[FF]]-[\x[22]\x[5C]\x[7F]]>+
        }
        token quotable-char {
            <[\t\x[20]..\x[FF]]-[\x[7F]]>
        }
        token quoted-pair {
            \\ <quotable-char>
        }
    }

    class HTTP::Header-Strict::Actions {
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
    
    multi method field ( HTTP::Header::ETag:D $etag ) {
        @.fields.push: $etag;
    }
    
    method parse($raw) {
        my $*OBJ = self;
        HTTP::Header-Strict::Grammar.parse:
                $raw,
                actions => HTTP::Header-Strict::Actions
                ;
    }
}

class HTTP::Message-Strict is HTTP::Message {
    #| see https://docs.raku.org/language/grammars#Attributes_in_grammars
    my constant $CRLF = "\x[0d]\x[0a]";
    my constant $DELIM = $CRLF x 2;
    
    method new($content?, *%fields) {
        my $header = HTTP::Header-Strict.new(|%fields);
        
        self.bless(:$header, :$content);
    }
    
    method parse ( $raw_message ) {
        my ( $start-line, $rest ) = $raw_message.split: $CRLF, 2;
        my ( $fields, $content ) = $rest.split: $DELIM, 2;
        
        my ($first, $second, $third) = $start-line.split(/\s+/);
        if $third.index('/') { # is a request
            $.protocol = $third;
        }
        else {               # is a response
            $.protocol = $first;
        }
        
        # $.header = HTTP::Header-Strict.new;
        $.header.parse: $fields;
        return self unless $content;
        
        if self.is-chunked {
            # technically incorrect - content allowed to contain embedded CRLFs
            my @lines = $content.split: $CRLF;
            # pop zero-length Str that occurs after last chunk
            #   what to do if this doesn't happen?
            @lines.pop if @lines %2;
            @lines = grep *,
                        @lines.map:
                                -> $d, $s { $d ~~ /^\d/ ?? $s !! Str }
                    ;
            $.content = @lines.join;
            return self;
        } else {
            $.content = $content;
            return self;
        }

        self
    }
    
    method Str ( :$debug, Bool :$bin ) {
        my constant $max_size = 300;
        # TODO : reference relevant section of relevant RFC
        # TODO : need to consider Str vs Buf length ?
        self.field: Content-Length => ( $.content.?encode or $.content ).bytes.Str
            if $.content and not self.is-chunked;
        my $s = $.header.Str: $CRLF;
        
        # The :bin will be passed from the H::UA
        if not $bin {
            # do not append CRLF unless chunked
            # https://datatracker.ietf.org/doc/html/rfc2616#section-4.3
            # https://datatracker.ietf.org/doc/html/rfc2616#section-7.2
            # https://datatracker.ietf.org/doc/html/rfc2616#section-14.41
            $s = join $CRLF, $s, $.content if $.content;
        }
        if $.content and $debug {
            if $bin || self.is-binary {
                $s ~= $CRLF ~ "=Content size : " ~ $.content.elems ~ " bytes ";
                $s ~= "$CRLF ** Not showing binary content ** $CRLF";
            }
            else {
                $s ~= $CRLF ~ "=Content size: "~$.content.Str.chars~" chars";
                $s ~= "- Displaying only $max_size" if $.content.Str.chars > $max_size;
                $s ~= $CRLF ~ $.content.Str.substr(0, $max_size) ~ $CRLF;
            }
        }

        $s
    }

}

class HTTP::Request-Strict is HTTP::Message-Strict is HTTP::Request {
    my constant $CRLF = "\x[0D]\x[0A]";
    
    
    sub get-host-value(URI $uri --> Str) {
        my Str $host = $uri.host;

        if $host {
            if ( $uri.port != $uri.default_port ) {
                $host ~= ':' ~ $uri.port;
            }
        }
        $host;
    }
    
    multi method new(Bool :$bin, *%args) {

        if %args {
            my ($method, $url, $file, %fields, $uri);
            for %args.kv -> $key, $value {
                if $key.lc ~~ any(<get post head put delete patch>) {
                    $uri = $value.isa(URI) ?? $value !! URI.new($value);
                    $method = $key.uc;
                }
                else {
                    %fields{$key} = $value;
                }
            }

            my $header = HTTP::Header-Strict.new(|%fields);
            self.new($method // 'GET', $uri, $header, :$bin);
        }
        else {
            self.bless: header => HTTP::Header-Strict.new
        }
    }

    multi method new() { self.bless: header => HTTP::Header-Strict.new }

    multi method new(HTTP::Request::RequestMethod $method, URI $uri, HTTP::Header-Strict $header, Bool :$bin) {
        my $url = $uri.grammar.parse_result.orig;
        my $file = $uri.path_query || '/';

        $header.field(Host => get-host-value($uri)) without $header.field('Host');

        self.bless(:$method, :$url, :$header, :$file, :$uri, binary => $bin)
    }
    
    method Str ( :$debug, Bool :$bin ) {
        $.file = '/' ~ $.file unless $.file.starts-with: '/';
        my $s = "$.method $.file $.protocol";
        join $CRLF, $s, self.HTTP::Message-Strict::Str: :$debug, :$bin;
    }
    method parse ( $raw_request ) {
        my @lines = $raw_request.split($CRLF);
        ($.method, $.file) = @lines.shift.split(' ');

        $.url = 'http://';

        for @lines -> $line {
            if $line ~~ m:i/host:/ {
                $.url ~= $line.split(/\:\s*/)[1];
            }
        }

        $.url ~= $.file;

        self.uri = URI.new($.url);
        self.HTTP::Message-Strict::parse: $raw_request;
    }
}

class HTTP::Response-Strict is HTTP::Response is HTTP::Message-Strict {
    my constant $CRLF = "\x[0D]\x[0A]";
    
    method next-request(--> HTTP::Request:D) {
        my HTTP::Request-Strict $new-request;

        my $location = ~self.header.field('Location').values;


        if $location.defined {
            # Special case for the HTTP status code 303 (redirection):
            # The response to the request can be found under another URI using
            # a separate GET method. This relates to POST, PUT, DELETE and PATCH
            # methods.
            my $method = $.request.method;
            $method = "GET"
            if self.code == 303
            && $.request.method eq any('POST', 'PUT', 'DELETE', 'PATCH');

            my %args = $method => $location;

            $new-request = HTTP::Request-Strict.new(|%args);

            unless ~$new-request.field('Host').values {
                my $hh = ~$.request.field('Host').values;
                $new-request.field(Host => $hh);
                $new-request.scheme = $.request.scheme;
                $new-request.host   = $.request.host;
                $new-request.port   = $.request.port;
            }
        }

        $new-request
    }
    
    method Str(:$debug) {
        my $s = $.protocol ~ " " ~ $.status-line;
        join $CRLF, $s, self.HTTP::Message-Strict::Str: :$debug;
    }
}

class HTTP::UserAgent-Strict is HTTP::UserAgent {
    constant CRLF = Buf.new(13, 10);
    
    role Connection {
        method send-request(HTTP::Request-Strict $request ) {
            $request.field(Connection => 'close') unless $request.field('Connection');
            if $request.binary {
                self.print($request.Str(:bin));
                self.write($request.content);
            } else {
                self.print: $request.Str;
            }
        }
    }
    
    multi sub basic-auth-token(Str $login, Str $passwd --> Str:D) {
        basic-auth-token("{$login}:{$passwd}");

    }

    multi sub basic-auth-token(Str $creds where * ~~ /':'/ --> Str:D) {
        "Basic " ~ MIME::Base64.encode-str($creds, :oneline);
    }
    
    multi method get(URI $uri is copy, Bool :$bin,  *%header ) {
        my $request  = HTTP::Request-Strict.new(GET => $uri, |%header);
        self.request($request, :$bin)
    }

    proto method post(|) {*}

    multi method post(URI $uri is copy, %form , Bool :$bin,  *%header) {
        my $request = HTTP::Request-Strict.new(POST => $uri, |%header);
        $request.add-form-data(%form);
        self.request($request, :$bin)
    }

    proto method put(|) {*}

    multi method put(URI $uri is copy, %form , Bool :$bin,  *%header) {
        my $request = HTTP::Request-Strict.new(PUT => $uri, |%header);
        $request.add-form-data(%form);
        self.request($request, :$bin)
    }

    proto method delete(|) {*}

    multi method delete(URI $uri is copy, Bool :$bin,  *%header ) {
        my $request  = HTTP::Request-Strict.new(DELETE => $uri, |%header);
        self.request($request, :$bin)
    }

    method request(HTTP::Request-Strict $request, Bool :$bin --> HTTP::Response-Strict:D) {
        my HTTP::Response-Strict $response;

        # add cookies to the request
        $request.add-cookies($.cookies);

        # set the useragent
        $request.field(User-Agent => $.useragent) if $.useragent.defined;

        # if auth has been provided add it to the request
        self.setup-auth($request);
        $.debug-handle.say("==>>Send\n" ~ $request.Str(:debug)) if $.debug;
        my Connection $conn = self.get-connection($request);

        if $conn.send-request($request) {
            $response = self.get-response($request, $conn, :$bin);
        }
        $conn.close;

        X::HTTP::Response.new(:rc('No response')).throw unless $response;

        $.debug-handle.say("<<==Recv\n" ~ $response.Str(:debug)) if $.debug;

        # save cookies
        $.cookies.extract-cookies($response);

        if $response.code ~~ /^30<[0123]>/ {
            $.redirects-in-a-row++;
            if $.max-redirects < $.redirects-in-a-row {
                X::HTTP::Response.new(:rc('Max redirects exceeded'), :response($response)).throw;
            }
            my $new-request = $response.next-request();
            return self.request($new-request);
        }
        else {
            $.redirects-in-a-row = 0;
        }
        if $.throw-exceptions {
            given $response.code {
                when /^4/ {
                    X::HTTP::Response.new(:rc($response.status-line), :response($response)).throw;
                }
                when /^5/ {
                    X::HTTP::Server.new(:rc($response.status-line), :response($response)).throw;
                }
            }
        }

        $response
    }
    
    multi method get-connection(HTTP::Request-Strict $request --> Connection:D) {
        my $host = $request.host;
        my $port = $request.port;


        if self.get-proxy($request) -> $http_proxy {
            $request.file = $request.url;
            my ($proxy_host, $proxy_auth) = $http_proxy.split('/').[2].split('@', 2).reverse;
            ($host, $port) = $proxy_host.split(':');
            $port.=Int;
            if $proxy_auth.defined {
                $request.field(Proxy-Authorization => basic-auth-token($proxy_auth));
            }
            $request.field(Connection => 'close');
        }
        self.get-connection($request, $host, $port)
    }

    my $https_lock = Lock.new;
    multi method get-connection(HTTP::Request-Strict $request, Str $host, Int $port? --> Connection:D) {
        my $conn;
        if $request.scheme eq 'https' {
            $https_lock.lock;
            try require ::("IO::Socket::SSL");
            $https_lock.unlock;
            die "Please install IO::Socket::SSL in order to fetch https sites" if ::('IO::Socket::SSL') ~~ Failure;
            $conn = ::('IO::Socket::SSL').new(:$host, :port($port // 443), :timeout($.timeout))
        }
        else {
            $conn = IO::Socket::INET.new(:$host, :port($port // 80), :timeout($.timeout));
        }
        $conn does Connection;
        $conn
    }
}
