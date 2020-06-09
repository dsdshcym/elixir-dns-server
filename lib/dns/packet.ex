defmodule DNS.Packet do
  def parse(<<header::binary-size(12), _rest::binary>>) do
    <<id::size(16), qr::size(1), opcode::size(4), aa::size(1), tc::size(1), rd::size(1),
      ra::size(1), z::size(3), rcode::size(4), qdcount::size(16), ancount::size(16),
      nscount::size(16), arcount::size(16)>> = header

    %{
      header: %{
        id: id,
        query_response: qr == 1,
        operation_code: opcode,
        authoritative_answer: aa == 1,
        truncated_message: tc == 1,
        recursion_desired: rd == 1,
        recursion_available: ra == 1,
        reserved: z,
        response_code: rcode,
        question_count: qdcount,
        answer_count: ancount,
        authority_count: nscount,
        additional_count: arcount
      }
    }
  end
end
