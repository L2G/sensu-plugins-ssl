module SensuPluginsSSL
  # This class holds methods responsible for taking sockets and performing a
  # STARTTLS handshake on them.
  module StarttlsHelper
    class << self
      # Very basic SMTP STARTTLS handshake. Wait for a 220 status, send a
      # STARTTLS command, then wait for another 220 status.
      #
      # @param socket [IO]
      # @raise [StarttlsHelper::HandshakeError] if either of the expected 220
      #   statuses are not received
      # @return [IO]
      def handshake_smtp(socket)
        status = socket.readline
        if /^220 /.match(status)
          socket.puts("STARTTLS")
        else
          fail HandshakeError, "Expected SMTP to return initial 220 status, instead got: #{status}"
        end

        status = socket.readline
        return socket if /^220 /.match(status)
        fail HandshakeError, "Expected SMTP to return 220 status after handshake, instead got: #{status}"
      end
    end

    # Raised by {StarttlsHelper} methods when a STARTTLS handshake does not go
    # as expected. The message should contain a human-readable explanation.
    class HandshakeError < RuntimeError; end
  end
end
