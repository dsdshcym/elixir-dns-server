defmodule DNS.Packet do
  def parse(binary) do
    with [header, rest] = parse_header(binary),
         [questions, _rest] = parse_questions(rest, header.question_count) do
      %{
        header: header,
        questions: questions
      }
    end
  end

  defp parse_header(<<
         id::size(16),
         qr::size(1),
         opcode::size(4),
         aa::size(1),
         tc::size(1),
         rd::size(1),
         ra::size(1),
         z::size(3),
         rcode::size(4),
         qdcount::size(16),
         ancount::size(16),
         nscount::size(16),
         arcount::size(16),
         rest::binary
       >>) do
    [
      %{
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
      },
      rest
    ]
  end

  defp parse_questions(binary, count, questions \\ [])

  defp parse_questions(rest, 0, questions) do
    [Enum.reverse(questions), rest]
  end

  defp parse_questions(binary, count, questions) do
    [question, rest] = parse_question(binary)
    parse_questions(rest, count - 1, [question | questions])
  end

  defp parse_question(binary) do
    [label, rest] = extract_label(binary)
    <<type::size(16), _class::size(16), rest::binary>> = rest

    type =
      case type do
        1 -> :A
      end

    [%{name: label, type: type}, rest]
  end

  defp extract_label(binary, label_parts \\ [])

  defp extract_label(<<0, rest::binary>>, label_parts) do
    [label_parts |> Enum.reverse() |> Enum.join("."), rest]
  end

  defp extract_label(<<len::size(8), label_part::binary-size(len), rest::binary>>, label_parts) do
    extract_label(rest, [label_part | label_parts])
  end
end
