"""Tests for the ftp_login module.

Some FTP servers put bytes that are not valid UTF-8 in their replies (localised
messages, or a server that simply does not care). ftplib decodes every reply
line with ``self.encoding``, which defaults to utf-8, so one such reply raises
UnicodeDecodeError out of ``FTP.getresp()``. patator only caught FTP_Error, so
the exception escaped and every candidate was reported as FAIL instead of being
judged on its status code (issue #237).

The tests below run a socket server on a loopback port that answers with
deliberately invalid UTF-8, and check that the module can still read the reply.
"""

import socket
import threading

import pytest

from patator.patator import FTP_login


# Replies containing 0xBE, which is not a valid UTF-8 start byte in this context.
BANNER = b'220 \xbe\xbe\xbe Fake FTP ready.\r\n'
USER_REPLY = b'331 \xbe Please specify the password.\r\n'
PASS_REPLY = b'530 \xbe\xbe Login incorrect.\r\n'

REPLIES = {
    b'USER': USER_REPLY,
    b'PASS': PASS_REPLY,
}


def _serve(sock):
    """Accept one client and answer the verbs in REPLIES."""
    conn, _ = sock.accept()
    conn.sendall(BANNER)
    buf = b''
    while True:
        try:
            data = conn.recv(1024)
        except OSError:
            break
        if not data:
            break
        buf += data
        while b'\r\n' in buf:
            line, buf = buf.split(b'\r\n', 1)
            verb = line.split(b' ')[0].upper()
            conn.sendall(REPLIES.get(verb, b'502 not implemented\r\n'))
    conn.close()


@pytest.fixture
def fake_ftp():
    """Start the server and yield its port, closing it afterwards."""
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    threading.Thread(target=_serve, args=(sock,), daemon=True).start()
    try:
        yield port
    finally:
        sock.close()


def test_connect_reads_non_utf8_banner(fake_ftp):
    """A reply containing 0xBE must not stop the connection from being read."""
    module = FTP_login()
    conn = module.connect('127.0.0.1', str(fake_ftp), '0', '5')

    banner = conn.fp.getwelcome()
    assert banner.startswith('220 ')
    assert 'Fake FTP ready.' in banner


def test_connect_does_not_raise_unicode_decode_error(fake_ftp):
    """Regression guard: this used to raise UnicodeDecodeError."""
    module = FTP_login()
    try:
        module.connect('127.0.0.1', str(fake_ftp), '0', '5')
    except UnicodeDecodeError as exc:  # pragma: no cover - only on regression
        pytest.fail('connect raised UnicodeDecodeError: %s' % exc)


if __name__ == '__main__':
    raise SystemExit(pytest.main([__file__, '-v']))
