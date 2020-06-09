defmodule DNS.PacketTest do
  use ExUnit.Case

  alias DNS.Packet

  describe "parse/1" do
    test "parses header" do
      query =
        <<0x86, 0x2A, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
          0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01,
          0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x25, 0x00, 0x04, 0xD8, 0x3A,
          0xD3, 0x8E>>

      assert match?(
               %{
                 header: %{
                   id: 0x862A,
                   recursion_desired: true,
                   truncated_message: false,
                   authoritative_answer: false,
                   operation_code: 0,
                   query_response: true,
                   reserved: 0,
                   response_code: 0,
                   recursion_available: true,
                   question_count: 1,
                   answer_count: 1,
                   authority_count: 0,
                   additional_count: 0
                 }
               },
               Packet.parse(query)
             )
    end
  end
end
