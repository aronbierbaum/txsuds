import logging
import re

from OpenSSL import SSL

from twisted.python.failure import Failure

from twisted.internet.ssl        import Certificate, VerificationError
from twisted.internet._sslverify import ClientTLSOptions, OpenSSLCertificateOptions, verifyHostname



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
        if where & SSL.SSL_CB_HANDSHAKE_START:
            connection.set_tlsext_host_name(self._hostnameBytes)
        elif where & SSL.SSL_CB_HANDSHAKE_DONE:
            if self._ctx.get_verify_mode() != SSL.VERIFY_NONE:
                try:
                    verifyHostname(connection, self._hostnameASCII)
                except VerificationError as ex:
                    log.error(str(ex))
                    f = Failure()
                    transport = connection.get_app_data()
                    transport.failVerification(f)

