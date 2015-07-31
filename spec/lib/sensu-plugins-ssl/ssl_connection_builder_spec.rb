describe SensuPluginsSSL::SSLConnectionBuilder do
  before(:each) do
    subject { described_class.new }
  end

  describe '#build_and_connect' do
    it 'internally creates a TCPSocket with the expected host and port' do
      # mock TCPSocket for isolation
      tcp_socket_class = class_double('TCPSocket').as_stubbed_const
      expect(tcp_socket_class).to receive(:new).with('8dxcsx7z', 9827)

      # mock OpenSSL::SSL::SSLSocket for isolation
      ssl_socket_class = class_double('OpenSSL::SSL::SSLSocket').as_stubbed_const
      ssl_socket = instance_double('OpenSSL::SSL::SSLSocket')
      allow(ssl_socket_class).to receive(:new).and_return(ssl_socket)
      allow(ssl_socket).to receive(:connect)
      allow(ssl_socket).to receive(:peer_cert)

      subject.build_and_connect('8dxcsx7z', 9827)
    end

    it 'internally creates an OpenSSL::SSL::SSLSocket using the TCPSocket' do
      # mock TCPSocket for isolation
      tcp_socket = double('TCPSocket instance')
      class_double('TCPSocket', new: tcp_socket).as_stubbed_const

      # mock OpenSSL::SSL::SSLSocket for isolation
      ssl_socket_class = class_double('OpenSSL::SSL::SSLSocket').as_stubbed_const
      ssl_socket = instance_double('OpenSSL::SSL::SSLSocket')
      expect(ssl_socket_class).to receive(:new).with(tcp_socket).and_return(ssl_socket)
      allow(ssl_socket).to receive(:connect)
      allow(ssl_socket).to receive(:peer_cert)

      subject.build_and_connect('fdshjkfds', 9281)
    end

    it 'creates a new SensuPluginsSSL::SSLConnection using the SSLSocket' do
      # mock TCPSocket for isolation
      tcp_socket = double('TCPSocket instance')
      class_double('TCPSocket', new: tcp_socket).as_stubbed_const

      # mock OpenSSL::SSL::SSLSocket for isolation
      ssl_socket_class = class_double('OpenSSL::SSL::SSLSocket').as_stubbed_const
      ssl_socket = instance_double('OpenSSL::SSL::SSLSocket')
      allow(ssl_socket_class).to receive(:new).and_return(ssl_socket)
      allow(ssl_socket).to receive(:connect)
      allow(ssl_socket).to receive(:peer_cert)

      # mock SensuPluginsSSL::SSLConnection for isolation
      ssl_connection_class = class_double('SensuPluginsSSL::SSLConnection').as_stubbed_const
      expect(ssl_connection_class).to receive(:new).with('copmcr7r', ssl_socket)
      subject.build_and_connect('copmcr7r', 7219)
    end

    it 'returns an instance of SensuPluginsSSL::SSLConnection' do
      # mock TCPSocket for isolation
      tcp_socket = double('TCPSocket instance')
      class_double('TCPSocket', new: tcp_socket).as_stubbed_const

      # mock OpenSSL::SSL::SSLSocket for isolation
      ssl_socket_class = class_double('OpenSSL::SSL::SSLSocket').as_stubbed_const
      ssl_socket = instance_double('OpenSSL::SSL::SSLSocket')
      allow(ssl_socket_class).to receive(:new).and_return(ssl_socket)
      allow(ssl_socket).to receive(:connect)
      allow(ssl_socket).to receive(:peer_cert)

      ssl_connection = subject.build_and_connect('zuzexs2v', 8272)
      expect(ssl_connection).to be_kind_of(SensuPluginsSSL::SSLConnection)
    end

    it 'accepts :starttls => "smtp" and triggers an SMTP STARTTLS handshake' do
      # mock TCPSocket for isolation
      tcp_socket = double('TCPSocket instance')
      allow(tcp_socket).to receive(:readline).and_return('This is an expected failure')
      class_double('TCPSocket', new: tcp_socket).as_stubbed_const

      # mock OpenSSL::SSL::SSLSocket for isolation
      ssl_socket_class = class_double('OpenSSL::SSL::SSLSocket').as_stubbed_const
      ssl_socket = instance_double('OpenSSL::SSL::SSLSocket')
      allow(ssl_socket_class).to receive(:new).and_return(ssl_socket)
      allow(ssl_socket).to receive(:connect)
      allow(ssl_socket).to receive(:peer_cert)

      # mock SensuPluginsSSL::StarttlsHandshake for isolation
      starttls_helper_class = class_double('SensuPluginsSSL::StarttlsHelper').as_stubbed_const
      expect(starttls_helper_class).to receive(:handshake_smtp).with(tcp_socket).and_return(tcp_socket)

      subject.build_and_connect('fsjhkwrue', 1928, starttls: 'smtp')
    end
  end
end
