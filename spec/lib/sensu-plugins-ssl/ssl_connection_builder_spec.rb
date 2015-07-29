describe SensuPluginsSSL::SSLConnectionBuilder do
  before(:each) do
    subject { described_class.new }
  end

  describe '#build_and_connect' do
    it 'creates a TCPSocket by default' do
      # "as_stubbed_const" is what allows a class double to fully stand in for
      # the real thing
      tcp_socket_class = class_double('TCPSocket').as_stubbed_const
      expect(tcp_socket_class).to receive(:new).with('8dxcsx7z', 9827)
      subject.build_and_connect('8dxcsx7z', 9827)
    end

    it 'creates a new SensuPluginsSSL::SSLConnection using the TCPSocket' do
      tcp_socket = double('TCPSocket instance')
      class_double('TCPSocket', new: tcp_socket).as_stubbed_const
      ssl_connection_class = class_double('SensuPluginsSSL::SSLConnection').as_stubbed_const
      expect(ssl_connection_class).to receive(:new).with('copmcr7r', tcp_socket)
      subject.build_and_connect('copmcr7r', 7219)
    end

    it 'returns an instance of SensuPluginsSSL::SSLConnection' do
      tcp_socket = double('TCPSocket instance')
      class_double('TCPSocket', new: tcp_socket).as_stubbed_const
      ssl_connection = subject.build_and_connect('zuzexs2v', 8272)
      expect(ssl_connection).to be_kind_of(SensuPluginsSSL::SSLConnection)
    end
  end
end
