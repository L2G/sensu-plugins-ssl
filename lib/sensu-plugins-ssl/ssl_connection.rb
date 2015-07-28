require 'openssl'
require 'socket'

module SensuPluginsSSL
  class SSLConnection
    attr_reader :host, :port

    def initialize(host, port)
      @host = host
      @port = port
    end

    def connect
      tcp_client = TCPSocket.new(host, port)
      @ssl_context = OpenSSL::SSL::SSLContext.new
      @ssl_client = OpenSSL::SSL::SSLSocket.new(tcp_client, @ssl_context)
      # SNI
      @ssl_client.hostname = host if @ssl_client.respond_to? :hostname=
      @ssl_client.connect
    end

    def close
      @ssl_client.close
      @ssl_client = nil
      @ssl_context = nil
    end
    alias_method :disconnect, :close

    def peer_cert_chain
      @ssl_client.peer_cert_chain
    end
  end
end
