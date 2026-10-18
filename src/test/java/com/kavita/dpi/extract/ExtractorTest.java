package com.kavita.dpi.extract;

import org.junit.jupiter.api.Test;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.*;

class ExtractorTest {

    private static byte[] clientHello(String host) {
        byte[] name = host.getBytes(StandardCharsets.US_ASCII);
        int sniExtLen = 2 + 1 + 2 + name.length;
        int extensionsLen = 4 + sniExtLen;
        int bodyLen = 43 + extensionsLen;

        ByteBuffer b = ByteBuffer.allocate(5 + 4 + bodyLen);
        b.put((byte) 0x16); b.putShort((short) 0x0301); b.putShort((short) (4 + bodyLen));
        b.put((byte) 0x01); b.put((byte) 0); b.putShort((short) bodyLen);
        b.putShort((short) 0x0303); b.put(new byte[32]);
        b.put((byte) 0);                                   // session ID length
        b.putShort((short) 2); b.putShort((short) 0x1301); // one cipher suite
        b.put((byte) 1); b.put((byte) 0);                  // one compression method
        b.putShort((short) extensionsLen);
        b.putShort((short) 0);                             // extension type: server_name
        b.putShort((short) sniExtLen);
        b.putShort((short) (1 + 2 + name.length));
        b.put((byte) 0); b.putShort((short) name.length); b.put(name);
        return b.array();
    }

    @Test
    void extractsSniFromClientHello() {
        byte[] hello = clientHello("WWW.YouTube.com");
        assertEquals("www.youtube.com",
                SniExtractor.extract(hello, 0, hello.length).orElseThrow());
    }

    @Test
    void truncatedClientHelloGivesEmptyNotException() {
        byte[] hello = clientHello("www.youtube.com");
        byte[] cut = Arrays.copyOf(hello, 30);
        assertTrue(SniExtractor.extract(cut, 0, cut.length).isEmpty());
    }

    @Test
    void nonTlsBytesGiveEmpty() {
        byte[] junk = new byte[50];
        assertTrue(SniExtractor.extract(junk, 0, junk.length).isEmpty());
    }

    @Test
    void extractsHostFromHttpRequest() {
        byte[] req = "GET / HTTP/1.1\r\nHost: Example.com:8080\r\nAccept: */*\r\n\r\n"
                .getBytes(StandardCharsets.ISO_8859_1);
        assertEquals("example.com",
                HttpHostExtractor.extract(req, 0, req.length).orElseThrow());
    }
}
