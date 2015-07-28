require 'date'
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
      tcp_socket = TCPSocket.new(host, port)
      @ssl_context = OpenSSL::SSL::SSLContext.new
      @ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, @ssl_context)
      # SNI
      @ssl_socket.hostname = host if @ssl_socket.respond_to? :hostname=
      @ssl_socket.connect
    end

    def close
      @ssl_socket.close
      @ssl_socket = nil
      @ssl_context = nil
    end
    alias_method :disconnect, :close

    # Days until the server certificate expires
    def days_until_expiry
      (peer_cert.not_after.to_date - Date.today).to_i
    end

    def peer_cert
      @ssl_socket.peer_cert
    end

    def peer_cert_chain
      @ssl_socket.peer_cert_chain
    end

    def peer_identity
      peer_cert.subject
    end

    def peer_identity_valid?
      OpenSSL::SSL.verify_certificate_identity(peer_cert, @host)
    end
  end
end
