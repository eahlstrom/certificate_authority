module CertificateAuthority
  module Revocable
    class InvalidCrlReason < StandardError; end

    class CrlReason
      CRL_REASONS = {
        'unspecified'           => 0,
        'keyCompromise'         => 1,
        'cACompromise'          => 2,
        'affiliationChanged'    => 3,
        'superseded'            => 4,
        'cessationOfOperation'  => 5,
        'certificateHold'       => 6,
        'removeFromCRL'         => 8,
        'privilegeWithdrawn'    => 9,
        'aACompromise'          => 10,
      }

      attr_reader :code, :reason

      def initialize(reason)
        @code = CRL_REASONS[reason]
        @reason = reason
        if @code.nil?
          raise(InvalidCrlReason,
                "Invalid reason: #{reason.inspect}. " +
                "Need a reason of #{CRL_REASONS.keys.join(', ')}")
        end
      end
    end

    attr_reader :revoked_at
    attr_reader :crl_reason

    def revoke!(reason, time=Time.now)
      @crl_reason = CrlReason.new(reason)
      @revoked_at = time
    end

    def revoked?
      # If we have a time, then we're revoked
      !@revoked_at.nil?
    end

    def revokation_reason
      crl_reason.nil? ? nil : crl_reason.reason
    end

    def revokation_reason_code
      crl_reason.nil? ? nil : crl_reason.code
    end

    def add_crl_reason?
      revokation_reason && revokation_reason != 'unspecified'
    end
  end
end
