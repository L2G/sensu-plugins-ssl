describe SensuPluginsSSL::SSLConnection do
  let(:ssl_socket) do
    ssl_socket = double('fake SSLSocket')
    allow(ssl_socket).to receive(:peer_cert)
    ssl_socket
  end

  subject do
    described_class.new('localhost', ssl_socket)
  end

  it { should respond_to(:cert_chain_valid?) }
  it { should respond_to(:close) }
  it { should respond_to(:days_until_expiry) }
  it { should respond_to(:disconnect) }
  it { should respond_to(:peer_cert) }
  it { should respond_to(:peer_cert_chain) }
  it { should respond_to(:peer_identity) }
  it { should respond_to(:peer_identity_valid?) }

  context 'defunct methods' do
    it { should_not respond_to(:connect) }
    it { should_not respond_to(:port) }
  end

  describe '.new' do
    it 'should accept an SSLSocket-like object' do
      expect { SensuPluginsSSL::SSLConnection.new('localhost', ssl_socket) }
        .not_to raise_error
    end

    it 'should raise an error if a non-SSLSocket-like object is given' do
      expect { SensuPluginsSSL::SSLConnection.new('this', 'should fail') }
        .to raise_error(ArgumentError)
    end
  end
end
