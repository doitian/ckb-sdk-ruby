# frozen_string_literal: true

require "bech32"
require "ckb/types/types"
require "ckb/version"
require "ckb/mode"
require "ckb/rpc"
require "ckb/api"
require "ckb/blake2b"
require "ckb/convert_address"
require "ckb/utils"
require "ckb/wallet"
require "ckb/address"
require "ckb/key"

require "ckb-sdk-ruby_jars" if RUBY_PLATFORM == "java"

module CKB
  class Error < StandardError; end
  # Your code goes here...
end
