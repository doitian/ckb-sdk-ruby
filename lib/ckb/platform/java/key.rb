# frozen_string_literal: true

require "securerandom"

java_import org.bouncycastle.crypto.digests.SHA256Digest
java_import org.bouncycastle.crypto.ec.CustomNamedCurves
java_import org.bouncycastle.crypto.params.ECDomainParameters
java_import org.bouncycastle.crypto.params.ECPrivateKeyParameters
java_import org.bouncycastle.crypto.signers.ECDSASigner
java_import org.bouncycastle.math.ec.FixedPointCombMultiplier
java_import org.bouncycastle.crypto.signers.HMacDSAKCalculator

module CKB
  class Key
    CURVE_PARAMS = CustomNamedCurves.get_by_name("secp256k1")
    CURVE = ECDomainParameters.new(
      CURVE_PARAMS.get_curve, CURVE_PARAMS.get_g, CURVE_PARAMS.get_n, CURVE_PARAMS.get_h
    )
    HALF_CURVE_ORDER = CURVE_PARAMS.get_n >> 1

    attr_reader :privkey, :pubkey, :address

    # @param privkey [String] hex string
    def initialize(privkey)
      raise ArgumentError, "invalid privkey!" unless privkey.instance_of?(String) && privkey.size == 66

      raise ArgumentError, "invalid hex string!" unless CKB::Utils.valid_hex_string?(privkey)

      @privkey = privkey

      @pubkey = self.class.pubkey(@privkey)

      @address = Address.from_pubkey(pubkey)
    end

    # @param data [String] hex string
    # @return [String] signature in hex string
    def sign(data)
      signer = ECDSASigner.new(HMacDSAKCalculator.new(SHA256Digest.new))
      privkey = ECPrivateKeyParameters.new(self.privkey.to_i(16), CURVE)
      signer.init(true, privkey)
      r, s, = signer.generate_signature(Utils.hex_to_bin(data).to_java_bytes)
      s = CURVE.get_n - s if s > HALF_CURVE_ORDER

      r = asn_uint256(r)
      s = asn_uint256(s)
      len = (r.size + s.size) / 2

      "0x30#{len.to_s(16)}#{r}#{s}"
    end

    def self.random_private_key
      candidate = CKB::Utils.bin_to_hex(SecureRandom.random_bytes(32))
      new(candidate)
      candidate
    rescue ArgumentError
      retry
    end

    def self.pubkey(privkey)
      privkey_bigint = privkey.to_i(16)
      raise ArgumentError, "invalid privkey!" if privkey_bigint >= CURVE.get_n

      point = FixedPointCombMultiplier.new.multiply(CURVE.get_g, privkey_bigint)
      Utils.bin_to_hex(String.from_java_bytes(point.getEncoded(true)))
    end

    private

    def asn_uint256(number)
      hex = number.to_s(16).rjust(64, "0")
      len = hex.size / 2
      if hex[0].to_i(16) >= 0b1000_0000
        len += 1
        # pad 0 before
        "02#{len.to_s(16)}00#{hex}"
      else
        "02#{len.to_s(16)}#{hex}"
      end
    end
  end
end
