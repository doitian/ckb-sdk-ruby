# frozen_string_literal: true

RSpec.describe CKB::Key do
  let(:privkey) { "0xe79f3207ea4980b7fed79956d5934249ceac4751a4fae01a0f7c4a96884bc4e3" }
  let(:pubkey) { "0x024a501efd328e062c8675f2365970728c859c592beeefd6be8ead3d901330bc01" }
  let(:address) { "0xbc374983430db3686ab181138bb510cb8f83aa136d833ac18fc3e73a3ad54b8b" }
  let(:privkey_bin) { Utils.hex_to_bin(privkey) }
  let(:pubkey_bin) { Utils.hex_to_bin(pubkey) }
  let(:pubkey_blake160) { "0x36c329ed630d6ce750712a477543672adab57f4c" }
  let(:pubkey_blake160_bin) { Utils.hex_to_bin(pubkey_blake160) }
  let(:prefix) { "ckt" }
  let(:address) { "ckt1q9gry5zgxmpjnmtrp4kww5r39frh2sm89tdt2l6v234ygf" }

  let(:key) { CKB::Key.new(privkey) }

  it "pubkey" do
    expect(key.pubkey).to eq pubkey
  end

  it "address" do
    expect(key.address.to_s).to eq address
  end

  describe "Out-of-bound Privkey" do
    let(:privkey) { "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141" }

    it "raise ArgumentError on out-of-bound privkey" do
      random = double
      allow(random).to receive(:random_bytes).and_return(
        CKB::Utils.hex_to_bin(privkey),
        CKB::Utils.hex_to_bin("0x#{(privkey.to_i(16) - 1).to_s(16)}")
      )
      stub_const("SecureRandom", random)

      expect(CKB::Key.random_private_key.to_i(16)).to eq(privkey.to_i(16) - 1)
    end
  end
end
