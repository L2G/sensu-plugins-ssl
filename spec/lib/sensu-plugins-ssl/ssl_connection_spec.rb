describe SensuPluginsSSL::SSLConnection do
  subject { described_class.new('localhost', '443') }

  it { should respond_to(:close) }
  it { should respond_to(:connect) }
  it { should respond_to(:disconnect) }
  it { should respond_to(:get_cert_chain) }
end
