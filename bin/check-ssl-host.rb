#!/usr/bin/env ruby
# encoding: UTF-8
#  check-ssl-host.rb
#
# DESCRIPTION:
#   SSL certificate checker
#   Connects to a HTTPS (or other SSL) server and performs several checks on
#   the certificate:
#     - Is the hostname valid for the host we're requesting
#     - If any certificate chain is presented, is it valid (i.e. is each
#       certificate signed by the next)
#     - Is the certificate about to expire
#   Currently no checks are performed to make sure the certificate is signed
#   by a trusted authority.
#
# DEPENDENCIES:
#   gem: sensu-plugin
#
# USAGE:
#   # Basic usage
#   check-ssl-host.rb -h <hostname>
#   # Specify specific days before cert expiry to alert on
#   check-ssl-host.rb -h <hostmame> -c <critical_days> -w <warning_days>
#   # Use -p to specify an alternate port
#   check-ssl-host.rb -h <hostname> -p 8443
#   # Use --skip-hostname-verification and/or --skip-chain-verification to
#   # disable some of the checks made.
#   check-ssl-host.rb -h <hostname> --skip-chain-verification
#
# LICENSE:
#   Copyright 2014 Chef Software, Inc.
#   Released under the same terms as Sensu (the MIT license); see LICENSE for
#   details.
#

require 'sensu-plugin/check/cli'
require 'sensu-plugins-ssl/ssl_connection_builder'

#
# Check SSL Host
#
class CheckSSLHost < Sensu::Plugin::Check::CLI
  attr_accessor :ssl_client, :ssl_context

  check_name 'check_ssl_host'

  option :critical,
         description: 'Return critical this many days before cert expiry',
         short: '-c',
         long: '--critical DAYS',
         proc: proc(&:to_i),
         default: 7

  option :warning,
         description: 'Return warning this many days before cert expiry',
         short: '-w',
         long: '--warning DAYS',
         required: true,
         proc: proc(&:to_i),
         default: 14

  option :host,
         description: 'Hostname of server to check',
         short: '-h',
         long: '--host HOST',
         required: true

  option :port,
         description: 'Port on server to check',
         short: '-p',
         long: '--port PORT',
         default: 443

  option :skip_hostname_verification,
         description: 'Disables hostname verification',
         long: '--skip-hostname-verification',
         boolean: true

  option :skip_chain_verification,
         description: 'Disables certificate chain verification',
         long: '--skip-chain-verification',
         boolean: true

  def verify_expiry(ssl_connection) # rubocop:disable all
    # Expiry check
    days = ssl_connection.days_until_expiry
    message = "#{config[:host]} - #{days} days until expiry"
    critical "#{config[:host]} - Expired #{days} days ago" if days < 0
    critical message if days < config[:critical]
    warning message if days < config[:warning]
    ok message
  end

  def verify_certificate_chain(ssl_connection)
    return if ssl_connection.cert_chain_valid?
    critical "#{config[:host]} - Invalid certificate chain"
  end

  def verify_hostname(ssl_connection)
    return if ssl_connection.peer_identity_valid?
    critical "#{config[:host]} hostname mismatch (#{ssl_connection.peer_identity})"
  end

  def run
    connection = SensuPluginsSSL::SSLConnectionBuilder.new.build_and_connect(config[:host], config[:port])
    verify_hostname(connection) unless config[:skip_hostname_verification]
    verify_certificate_chain(connection) unless config[:skip_chain_verification]
    verify_expiry(connection)
    connection.close
  end
end
