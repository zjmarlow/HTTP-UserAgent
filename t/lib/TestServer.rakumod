module TestServer {

    sub test-server(Promise $done-promise, Int :$port --> Promise:D) is export {
        my $server-promise = start {
            sub _index_buf(Blob $input, Blob $sub) {
                my $end-pos = 0;
                while $end-pos < $input.bytes {
                    if $sub eq $input.subbuf($end-pos, $sub.bytes) {
                        return $end-pos;
                    }
                    $end-pos++;
                }
                return -1;
            }
            react {
                whenever $done-promise {
                    die $_;
                    done;
                }
                whenever IO::Socket::Async.listen('localhost',$port) -> $conn {
                    my Buf $in-buf = Buf.new;
                    my Str $req-line;
                    whenever $conn.Supply(:bin) -> $buf { 
                        if $in-buf.elems == 0 {
                            my $header-end = _index_buf($buf, Buf.new(13,10));
                            $req-line = $buf.subbuf(0, $header-end).decode;
                            $in-buf ~= $buf.subbuf($header-end + 2);
                        }
                        else {
                            $in-buf ~= $buf;
                        }


                        if (my $header-end = _index_buf($in-buf, Buf.new(13,10,13,10))) > 0 {
                            my $header = $in-buf.subbuf(0, $header-end).decode('ascii');

                            if $req-line ~~ /^GET \s+ \/one/ {
                                $conn.write: "HTTP/1.1 302 Found\r\nLocation: /two\r\nSet-Cookie: test=abc\r\n\r\n".encode;
                                $conn.close;
                            }

                            elsif $req-line ~~ /^GET \s+ \/?two/ {
                                if ( $header ~~ /Cookie\: \s+ test\=abc/ ) {
                                    $conn.write: "HTTP/1.1 200 OK\r\n\r\n".encode;
                                } else {
                                    $conn.write: "HTTP/1.1 404 Not Found\r\n\r\n".encode;
                                }
                                $conn.close;
                            }

                            elsif $header ~~ /Content\-Length\:\s+$<length>=[\d+]/ {
                                my $length = $<length>.Int; 
                                if $in-buf.subbuf($header-end + 4) == $length {
                                    await $conn.write: "HTTP/1.0 200 OK\r\n".encode ~ $in-buf ;
                                    $conn.close;
                                }
                            }
                        }
                    } 
                }
            }
        }
        $server-promise
    }
    
    use HTTP::Request;
    my constant $STRICT = True;
    sub test-full-message ( Promise $done-promise, Int :$port --> Promise:D ) is export {
        start {
            react {
                whenever $done-promise {
                    done;
                }
                whenever IO::Socket::Async.listen: 'localhost', $port -> $conn {
                    whenever $conn.Supply: :bin -> $buf {
                        my HTTP::Request $r = HTTP::Request.new: $STRICT;
                        $r.parse: $buf.decode, $STRICT;
                        my ( $eol, $okl );
                        $eol = $r.content.ends-with: "\x0d\x0a";
                        $okl = $r.content.chars == .values.head.Int with $r.field: 'Content-Length';
                        my $out-buf =
                            Buf.new:
                                    'HTTP/1.1 200 OK'.comb>>.ord, 13, 10,
                                    'Content-Length: 3'.comb>>.ord, 13, 10,
                                    13, 10,
                                    ( $eol ?? 'T'.ord !! 'F'.ord ), 13, ( $okl ?? 'T'.ord !! 'F'.ord );
                        $conn.write: $out-buf;
                        $conn.close;
                    }
                }
            }
        }
    }
}

# vim: expandtab shiftwidth=4
