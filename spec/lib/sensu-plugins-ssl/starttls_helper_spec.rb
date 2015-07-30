require 'sensu-plugins-ssl/starttls_helper'

describe SensuPluginsSSL::StarttlsHelper do
  specify { expect(described_class).to respond_to(:handshake_smtp).with(1).argument }

  describe '.handshake_smtp' do
    it 'looks for initial OK from SMTP server' do
      # mock SMTP
      fake_socket = double('fake SMTP server')
      expect(fake_socket).to receive(:readline).with(no_args).and_return("220 fake SMTP server ready\r\n")
      allow(fake_socket).to receive(:puts).with("STARTTLS")
      allow(fake_socket).to receive(:readline).with(no_args).and_return("220 Here's where the TLS negotiation begins\r\n")

      described_class.handshake_smtp(fake_socket)
    end

    it 'sends STARTTLS after receiving initial OK from SMTP server' do
      # mock SMTP
      fake_socket = double('fake SMTP server')
      allow(fake_socket).to receive(:readline).with(no_args).and_return("220 fake SMTP server ready\r\n")
      allow(fake_socket).to receive(:puts)
      allow(fake_socket).to receive(:readline).with(no_args).and_return("220 Here's where the TLS negotiation begins\r\n")

      described_class.handshake_smtp(fake_socket)
      expect(fake_socket).to have_received(:puts).with("STARTTLS")
    end

    it 'raises HandshakeError if initial OK is not received from server' do
      # mock SMTP
      fake_socket = double('fake SMTP server')
      allow(fake_socket).to receive(:readline).with(no_args).and_return("Who is this?\n")
       
      expect do
        described_class.handshake_smtp(fake_socket)
      end.to raise_error(SensuPluginsSSL::StarttlsHelper::HandshakeError,
                         /Expected SMTP to return initial 220 status, instead got: Who is this\?/)
    end

    it 'raises no error if SMTP returns 220 after handshake' do
      # mock SMTP
      fake_socket = double('fake SMTP server')
      expect(fake_socket).to receive(:readline).with(no_args).and_return("220 fake SMTP server ready\r\n")
      allow(fake_socket).to receive(:puts).with("STARTTLS")
      expect(fake_socket).to receive(:readline).with(no_args).and_return("220 Here's where the TLS negotiation begins\r\n")

      expect { described_class.handshake_smtp(fake_socket) }.not_to raise_error
    end

    it 'raises an error if SMTP does not return 220 after handshake' do
      # mock SMTP
      fake_socket = double('fake SMTP server')
      expect(fake_socket).to receive(:readline).with(no_args).and_return("220 fake SMTP server ready\r\n")
      allow(fake_socket).to receive(:puts).with("STARTTLS")
      expect(fake_socket).to receive(:readline).with(no_args).and_return("454 No TLS for you!\r\n")

      expect do
        described_class.handshake_smtp(fake_socket)
      end.to raise_error(SensuPluginsSSL::StarttlsHelper::HandshakeError,
                         /Expected SMTP to return 220 status after handshake, instead got: 454 No TLS for you!/)
    end
  end
end
