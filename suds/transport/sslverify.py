import logging
import re

from OpenSSL import SSL

from twisted.python.failure import Failure

from twisted.internet.ssl        import Certificate
from twisted.internet._sslverify import (ClientTLSOptions, OpenSSLCertificateOptions,
                                         _maybeSetHostNameIndication, SSL_CB_HANDSHAKE_START,
                                         SSL_CB_HANDSHAKE_DONE)


log = logging.getLogger(__name__)


def optionsForClientTLS(hostname, trustRoot=None, clientCertificate=None, **kw):
    """
    Reimplemented from twisted.internet.ssl to allow extra parameters to be passed correctly.

    @return: A client connection creator.
    @rtype: L{IOpenSSLClientConnectionCreator}
    """
    extraCertificateOptions = kw.pop('extraCertificateOptions', None) or {}
    if kw:
        raise TypeError(
            "optionsForClientTLS() got an unexpected keyword argument"
            " '{arg}'".format(
                arg=kw.popitem()[0]
            )
        )
    if not isinstance(hostname, unicode):
        raise TypeError(
            "optionsForClientTLS requires text for host names, not "
            + hostname.__class__.__name__
        )
    if clientCertificate:
        extraCertificateOptions.update(
            privateKey=clientCertificate.privateKey.original,
            certificate=clientCertificate.original
        )

    # Only pass the trustRoot if it is not None to avoid mutually exclusive param issues.
    if trustRoot:
        certificateOptions = OpenSSLCertificateOptions(
            trustRoot=trustRoot,
            **extraCertificateOptions
        )
    else:
        certificateOptions = OpenSSLCertificateOptions(**extraCertificateOptions)

    return SSLClientConnectionCreator(hostname, certificateOptions.getContext())


class CertMatchError(ValueError):
    """
    Raised when we fail to match an SSL certificate to a hostname.
    """
    pass


def _dnsNameMatch(name, hostname, maxWildcards = 1):
    """
    Matching according to RFC 6125, section 6.4.3
    @type  name:         basestring
    @param name:         The name/value to check against the hostname.
    @type  hostname:     basestring
    @param hostname:     Hostname to check against.
    @type  maxWildcards: int
    @param maxWildcards: The maximum number of wildcards to allow in name.
    http://tools.ietf.org/html/rfc6125#section-6.4.3
    """
    pats = []
    if not name:
        return False

    # Ported from python3-syntax:
    # leftmost, *remainder = name.split(r'.')
    parts = name.split(r".")
    leftmost = parts[0]
    remainder = parts[1:]

    wildcards = leftmost.count("*")
    if wildcards > maxWildcards:
        # Issue #17980: avoid denials of service by refusing more
        # than one wildcard per fragment.  A survey of established
        # policy among SSL implementations showed it to be a
        # reasonable choice.
        raise CertMatchError("Too many wildcards in certificate DNS name: %s" % (name))

    # speed up common case w/o wildcards
    if not wildcards:
        return name.lower() == hostname.lower()

    # RFC 6125, section 6.4.3, subitem 1.
    # The client SHOULD NOT attempt to match a presented identifier in which
    # the wildcard character comprises a label other than the left-most label.
    if leftmost == "*":
        # When "*" is a fragment by itself, it matches a non-empty dotless
        # fragment.
        pats.append("[^.]+")
    elif leftmost.startswith("xn--") or hostname.startswith("xn--"):
        # RFC 6125, section 6.4.3, subitem 3.
        # The client SHOULD NOT attempt to match a presented identifier
        # where the wildcard character is embedded within an A-label or
        # U-label of an internationalized domain name.
        pats.append(re.escape(leftmost))
    else:
       # Otherwise, "*" matches any dotless string, e.g. www*
        pats.append(re.escape(leftmost).replace(r"\*", "[^.]*"))

    # add the remaining fragments, ignore any wildcards
    for frag in remainder:
        pats.append(re.escape(frag))

    return re.match(r"\A" + r"\.".join(pats) + r"\Z", hostname, re.IGNORECASE) is not None


def _matchHostname(cert, hostname):
    """
    The match_hostname() function from Python 3.3.3
    Verify that L{cert} matches the L{hostname}. RFC 2818 and RFC 6125 rules
    are followed, but IP addresses are not accepted for L{hostname}.
    @type  cert:     L{twisted.internet.ssl.Certificate}
    @param cert:     SSL certificate to verify hostname for.
    @type  hostname: basestring
    @param hostname: Hostname to check against.
    CertMatchError is raised on failure. On success, the function returns nothing.
    """
    # The common name is only checked when there are no DNS entries in the SAN.
    common_name = cert.original.get_subject().commonName
    if not _dnsNameMatch(common_name, hostname):
        raise CertMatchError("Hostname %s doesn't match %s" % (hostname, common_name))


class SSLClientConnectionCreator(ClientTLSOptions):
    """
    Client creator for TLS.

    Extends ClientTLSOptions to allow skipping verification and to improve
    twisted's base verification.
    """
    def _identityVerifyingInfoCallback(self, connection, where, ret):
        """
        Override the base implementation to provide better hostname verification.

        @param connection: the connection which is handshaking.
        @type connection: L{OpenSSL.SSL.Connection}

        @param where: flags indicating progress through a TLS handshake.
        @type where: L{int}

        @param ret: ignored
        @type ret:  ignored
        """
        if where & SSL_CB_HANDSHAKE_START:
            _maybeSetHostNameIndication(connection, self._hostnameBytes)
        elif where & SSL_CB_HANDSHAKE_DONE:
            if self._ctx.get_verify_mode() != SSL.VERIFY_NONE:
                try:
                    peer_cert = Certificate(connection.get_peer_certificate())
                    _matchHostname(peer_cert, self._hostname)
                except CertMatchError as ex:
                    log.error(str(ex))
                    f = Failure()
                    transport = connection.get_app_data()
                    transport.failVerification(f)

