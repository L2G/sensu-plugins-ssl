require 'date'
require 'openssl'

module SensuPluginsSSL
  # This class is intended to wrap an <OpenSSL::SSL::SSLSocket> and provide
  # friendly methods for verifying aspects of the connection (peer certificate
  # validity and age, etc.)
  class SSLConnection
    attr_reader :host

    # Setting up a new SSL/TLS connection is a complicated process.  The
    # {SensuPluginsSSL::SSLConnectionBuilder} class is provided as a convenient
    # factory for creating new instances of this class.
    #
    # @param host [String] hostname of the peer on the other end of the connection
    # @param ssl_socket [#peer_cert] an existing instance of
    #   OpenSSL::SSL::SSLSocket or descendant, which should already be connected
    def initialize(host, ssl_socket)
      @host = host
      @ssl_socket = ssl_socket

      unless @ssl_socket.respond_to?(:peer_cert)
        raise ArgumentError, "Should have received some kind of SSLSocket object; got this instead: #{ssl_socket}"
      end
    end

    # Validates that every certificate in the chain used by this connection is
    # signed by the next.
    #
    # NOTE: This *doesn't* validate that the top of the chain is signed by a
    # trusted CA.
    #
    # @return true if every cert in the chain is signed by the next; false
    #   otherwise
    def cert_chain_valid?
      valid = true
      parent = nil
      peer_cert_chain.reverse_each do |c|
        if parent
          valid &= c.verify(parent.public_key)
        end
        parent = c
      end
      valid
    end

    # @api private
    def close
      @ssl_socket.close
      @ssl_socket = nil
      @ssl_context = nil
    end
    alias_method :disconnect, :close

    # Days until the server's certificate expires
    def days_until_expiry
      (peer_cert.not_after.to_date - Date.today).to_i
    end

    # @api private
    def peer_cert
      @ssl_socket.peer_cert
    end

    # @api private
    def peer_cert_chain
      @ssl_socket.peer_cert_chain
    end

    # The subject of the peer's X.509 certificate
    #
    # May be used in diagnostic messages, e.g. if {#peer_identity_valid?} is
    # false and the user needs an idea of why.
    #
    # @return [String]
    def peer_identity
      peer_cert.subject
    end

    # Whether the hostname matches the identity provided in the server's
    # certificate
    #
    # @return true if the hostname matches the server certificate; false
    #   otherwise
    def peer_identity_valid?
      OpenSSL::SSL.verify_certificate_identity(peer_cert, @host)
    end
  end
end
