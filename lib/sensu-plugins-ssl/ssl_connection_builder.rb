require 'socket'
require 'sensu-plugins-ssl/ssl_connection'

module SensuPluginsSSL
  # This class has the responsibility of opening a new SSL/TLS connection,
  # optionally negotiating with STARTTLS, then returning the prepared connection
  # as a <SensuPluginsSSL::SSLConnection>.
  class SSLConnectionBuilder
    def build_and_connect(host, port)
      tcp_socket = TCPSocket.new(host, port)
      ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket)

      # SNI
      ssl_socket.hostname = host if ssl_socket.respond_to? :hostname=
      ssl_socket.connect

      SensuPluginsSSL::SSLConnection.new(host, ssl_socket)
    end
  end
end
