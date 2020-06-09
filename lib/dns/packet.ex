defmodule DNS.Packet do
  def parse(binary) do
    with [header, rest] = parse_header(binary),
         [questions, rest] = parse_questions(rest, binary, header.question_count),
         [answers, _rest] = parse_answers(rest, binary, header.answer_count) do
      %{
        header: header,
        questions: questions,
        answers: answers
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

  defp parse_questions(rest, _binary, count, questions \\ [])

  defp parse_questions(rest, _binary, 0, questions) do
    [Enum.reverse(questions), rest]
  end

  defp parse_questions(rest, binary, count, questions) do
    [question, rest] = parse_question(rest, binary)
    parse_questions(rest, binary, count - 1, [question | questions])
  end

  defp parse_question(rest, binary) do
    [label, rest] = extract_label(rest, binary)
    <<type::size(16), _class::size(16), rest::binary>> = rest

    type =
      case type do
        1 -> :A
      end

    [%{name: label, type: type}, rest]
  end

  defp parse_answers(rest, binary, count, answers \\ [])

  defp parse_answers(rest, _binary, 0, answers) do
    [Enum.reverse(answers), rest]
  end

  defp parse_answers(rest, binary, count, answers) do
    [answer, rest] = parse_answer(rest, binary)

    parse_answers(rest, binary, count - 1, [answer | answers])
  end

  defp parse_answer(rest, binary) do
    [label, rest] = extract_label(rest, binary, [])

    <<_type::size(16), _class::size(16), ttl::size(32), len::size(16), ip::bytes-size(len),
      rest::binary>> = rest

    [
      %{
        ttl: ttl,
        domain: label,
        addr: ip |> :binary.bin_to_list() |> List.to_tuple()
      },
      rest
    ]
  end

  defp extract_label(rest, binary, label_parts \\ [])

  defp extract_label(<<1::size(1), 1::size(1), pos::size(14), rest::binary>>, binary, label_parts) do
    <<_::bytes-size(pos), jump::bytes>> = binary
    [label, _] = extract_label(jump, binary)

    label_parts = [label | label_parts]
    [label_parts |> Enum.reverse() |> Enum.join("."), rest]
  end

  defp extract_label(<<0, rest::binary>>, _binary, label_parts) do
    [label_parts |> Enum.reverse() |> Enum.join("."), rest]
  end

  defp extract_label(
         <<len::size(8), label_part::binary-size(len), rest::binary>>,
         binary,
         label_parts
       ) do
    extract_label(rest, binary, [label_part | label_parts])
  end
end
