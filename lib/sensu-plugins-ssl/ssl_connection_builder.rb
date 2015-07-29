require 'socket'
require 'sensu-plugins-ssl/ssl_connection'

module SensuPluginsSSL
  # This class has the responsibility of opening a new SSL/TLS connection,
  # optionally negotiating with STARTTLS, then returning the prepared connection
  # as a <SensuPluginsSSL::SSLConnection>.
  class SSLConnectionBuilder
    def build_and_connect(host, port)
      tcp_socket = TCPSocket.new(host, port)
      SSLConnection.new(host, tcp_socket)
    end
  end
end
