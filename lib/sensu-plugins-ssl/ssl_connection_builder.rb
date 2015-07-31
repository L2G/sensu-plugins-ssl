require 'socket'
require 'sensu-plugins-ssl/ssl_connection'
require 'sensu-plugins-ssl/starttls_helper'

module SensuPluginsSSL
  # This class has the responsibility of opening a new SSL/TLS connection,
  # optionally negotiating with STARTTLS, then returning the prepared connection
  # as a {SensuPluginsSSL::SSLConnection}.
  class SSLConnectionBuilder
    # Open a new SSL/TLS connection wrapped up in a
    # {SensuPluginsSSL::SSLConnection} instance.  This uses TCPSocket and
    # OpenSSL::SSL::SSLSocket to make the connection, and may invoke methods on
    # {SensuPluginsSSL::StarttlsHelper} if necessary.
    #
    # @param [String] host the remote server to connect to
    # @param [Integer, String] port the TCP port to connect to on the remote
    #   server
    # @param [Hash] extra_args
    # @option extra_args [String, optional] :starttls use the named protocol's
    #   STARTTLS negotiation (only "smtp" is supported at this time)
    # @return [SensuPluginsSSL::SSLConnection]
    def build_and_connect(host, port, extra_args = {})
      tcp_socket = TCPSocket.new(host, port)

      # STARTTLS
      starttls = extra_args[:starttls]
      case starttls
      when 'smtp'
        StarttlsHelper.send("handshake_#{starttls}", tcp_socket)
      when nil
        # do nothing
      else
        fail ArgumentError, ":starttls argument #{starttls.inspect} not recognized"
      end

      ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket)

      # SNI
      ssl_socket.hostname = host if ssl_socket.respond_to? :hostname=
      ssl_socket.connect

      SensuPluginsSSL::SSLConnection.new(host, ssl_socket)
    end
  end
end
