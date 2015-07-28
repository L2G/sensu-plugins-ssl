describe SensuPluginsSSL::SSLConnection do
  subject { described_class.new('localhost', '443') }

  it { should respond_to(:close) }
  it { should respond_to(:connect) }
  it { should respond_to(:days_until_expiry) }
  it { should respond_to(:disconnect) }
  it { should respond_to(:peer_cert) }
  it { should respond_to(:peer_cert_chain) }
  it { should respond_to(:peer_identity) }
  it { should respond_to(:peer_identity_valid?) }
end
