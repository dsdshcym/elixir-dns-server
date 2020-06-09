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

    test "parses one question" do
      query =
        <<0x86, 0x2A, 0x81, 0x80, 0, 1, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6F,
          0x6F, 0x67, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01, 0xC0,
          0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x25, 0x00, 0x04, 0xD8, 0x3A, 0xD3,
          0x8E>>

      assert match?(
               %{
                 questions: [
                   %{name: "google.com", type: :A}
                 ]
               },
               Packet.parse(query)
             )
    end

    test "parses multiple questions" do
      query =
        <<0x86, 0x2A, 0x81, 0x80, 0, 2, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6F,
          0x6F, 0x67, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01, 0x06,
          0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00,
          0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x25, 0x00, 0x04, 0xD8,
          0x3A, 0xD3, 0x8E>>

      assert match?(
               %{
                 questions: [
                   %{name: "google.com", type: :A},
                   %{name: "google.com", type: :A}
                 ]
               },
               Packet.parse(query)
             )
    end

    test "parses one answer" do
      query =
        <<0x86, 0x2A, 0x81, 0x80, 0x00, 0x01, 0, 1, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6F,
          0x6F, 0x67, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01, 0xC0,
          0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x25, 0x00, 0x04, 0xD8, 0x3A, 0xD3,
          0x8E>>

      assert match?(
               %{
                 answers: [
                   %{domain: "google.com", addr: {216, 58, 211, 142}, ttl: 293}
                 ]
               },
               Packet.parse(query)
             )
    end

    test "parses multiple answers" do
      query =
        <<0x86, 0x2A, 0x81, 0x80, 0x00, 0x02, 0, 2, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6F,
          0x6F, 0x67, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01, 0x06,
          0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00,
          0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x25, 0x00, 0x04, 0xD8,
          0x3A, 0xD3, 0x8E, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x25, 0x00,
          0x04, 0xD8, 0x3A, 0xD3, 0x8E>>

      assert match?(
               %{
                 answers: [
                   %{domain: "google.com", addr: {216, 58, 211, 142}, ttl: 293},
                   %{domain: "google.com", addr: {216, 58, 211, 142}, ttl: 293}
                 ]
               },
               Packet.parse(query)
             )
    end

    test "query packet" do
      query =
        <<0x2A, 0xD0, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
          0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01>>

      assert match?(
               %{
                 answers: [],
                 header: %{
                   additional_count: 0,
                   answer_count: 0,
                   authoritative_answer: false,
                   authority_count: 0,
                   id: 10960,
                   operation_code: 0,
                   query_response: false,
                   question_count: 1,
                   recursion_available: false,
                   recursion_desired: true,
                   reserved: 2,
                   response_code: 0,
                   truncated_message: false
                 },
                 questions: [%{name: "google.com", type: :A}]
               },
               Packet.parse(query)
             )
    end

    test "query baidu.com" do
      query =
        <<0x52, 0x99, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x62,
          0x61, 0x69, 0x64, 0x75, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01>>

      assert match?(
               %{
                 answers: [],
                 header: %{
                   additional_count: 0,
                   answer_count: 0,
                   authoritative_answer: false,
                   authority_count: 0,
                   id: 21145,
                   operation_code: 0,
                   query_response: false,
                   question_count: 1,
                   recursion_available: false,
                   recursion_desired: true,
                   reserved: 2,
                   response_code: 0,
                   truncated_message: false
                 },
                 questions: [%{name: "baidu.com", type: :A}]
               },
               Packet.parse(query)
             )

      answer =
        <<0x52, 0x99, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x05, 0x62,
          0x61, 0x69, 0x64, 0x75, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01, 0xC0,
          0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x34, 0x00, 0x04, 0x27, 0x9C, 0x45,
          0x4F, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x34, 0x00, 0x04, 0xDC,
          0xB5, 0x26, 0x94>>

      assert match?(
               %{
                 answers: [
                   %{addr: {39, 156, 69, 79}, domain: "baidu.com", ttl: 308},
                   %{addr: {220, 181, 38, 148}, domain: "baidu.com", ttl: 308}
                 ],
                 header: %{
                   additional_count: 0,
                   answer_count: 2,
                   authoritative_answer: false,
                   authority_count: 0,
                   id: 21145,
                   operation_code: 0,
                   query_response: true,
                   question_count: 1,
                   recursion_available: true,
                   recursion_desired: true,
                   reserved: 0,
                   response_code: 0,
                   truncated_message: false
                 },
                 questions: [%{name: "baidu.com", type: :A}]
               },
               Packet.parse(answer)
             )
    end

    test "support message compression when a domain name is represented as a sequence of labels ending with a pointer" do
      answer =
        <<0x52, 0x99, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x05, 0x62,
          0x61, 0x69, 0x64, 0x75, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01, 0x05,
          0x62, 0x61, 0x69, 0x64, 0x75, 0xC0, 18, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x34,
          0x00, 0x04, 0x27, 0x9C, 0x45, 0x4F, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
          0x01, 0x34, 0x00, 0x04, 0xDC, 0xB5, 0x26, 0x94>>

      assert match?(
               %{
                 answers: [
                   %{addr: {39, 156, 69, 79}, domain: "baidu.com", ttl: 308},
                   %{addr: {220, 181, 38, 148}, domain: "baidu.com", ttl: 308}
                 ],
                 header: %{
                   additional_count: 0,
                   answer_count: 2,
                   authoritative_answer: false,
                   authority_count: 0,
                   id: 21145,
                   operation_code: 0,
                   query_response: true,
                   question_count: 1,
                   recursion_available: true,
                   recursion_desired: true,
                   reserved: 0,
                   response_code: 0,
                   truncated_message: false
                 },
                 questions: [%{name: "baidu.com", type: :A}]
               },
               Packet.parse(answer)
             )
    end

    test "support CNAME" do
      query =
        <<0x1F, 0x00, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
          0x77, 0x77, 0x05, 0x62, 0x61, 0x69, 0x64, 0x75, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00,
          0x01, 0x00, 0x01>>

      assert match?(
               %{
                 answers: [],
                 header: %{
                   additional_count: 0,
                   answer_count: 0,
                   authoritative_answer: false,
                   authority_count: 0,
                   id: 7936,
                   operation_code: 0,
                   query_response: false,
                   question_count: 1,
                   recursion_available: false,
                   recursion_desired: true,
                   reserved: 2,
                   response_code: 0,
                   truncated_message: false
                 },
                 questions: [%{name: "www.baidu.com", type: :A}]
               },
               Packet.parse(query)
             )

      answer =
        <<0x1F, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
          0x77, 0x77, 0x05, 0x62, 0x61, 0x69, 0x64, 0x75, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00,
          0x01, 0x00, 0x01, 0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0xE3, 0x00,
          0x0F, 0x03, 0x77, 0x77, 0x77, 0x01, 0x61, 0x06, 0x73, 0x68, 0x69, 0x66, 0x65, 0x6E,
          0xC0, 0x16, 0xC0, 0x2B, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3E, 0x00, 0x0E,
          0x03, 0x77, 0x77, 0x77, 0x07, 0x77, 0x73, 0x68, 0x69, 0x66, 0x65, 0x6E, 0xC0, 0x16,
          0xC0, 0x46, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x76, 0x00, 0x04, 0x67, 0xEB,
          0x2E, 0x27>>

      assert match?(
               %{
                 answers: [
                   %{domain: "www.baidu.com", host: "www.a.shifen.com", ttl: 483},
                   %{domain: "www.a.shifen.com", host: "www.wshifen.com", ttl: 62},
                   %{addr: {103, 235, 46, 39}, domain: "www.wshifen.com", ttl: 118}
                 ],
                 header: %{
                   additional_count: 0,
                   answer_count: 3,
                   authoritative_answer: false,
                   authority_count: 0,
                   id: 7936,
                   operation_code: 0,
                   query_response: true,
                   question_count: 1,
                   recursion_available: true,
                   recursion_desired: true,
                   reserved: 0,
                   response_code: 0,
                   truncated_message: false
                 },
                 questions: [%{name: "www.baidu.com", type: :A}]
               },
               Packet.parse(answer)
             )
    end
  end
end
