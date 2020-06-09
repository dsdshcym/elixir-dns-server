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

    <<type_enum::size(16), _class::size(16), rest::binary>> = rest

    [build_question(label, type_enum), rest]
  end

  defp build_question(name, type_enum) when is_number(type_enum) do
    build_question(name, resolve_type(type_enum))
  end

  defp build_question(name, type) when is_atom(type) do
    %{name: name, type: type}
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

    <<type_enum::size(16), _class::size(16), ttl::size(32), len::size(16), ip::bytes-size(len),
      rest::binary>> = rest

    answer = build_answer(label, type_enum, ttl, ip, binary)

    [answer, rest]
  end

  defp build_answer(domain, type_enum, ttl, rdata, binary) when is_number(type_enum) do
    build_answer(domain, resolve_type(type_enum), ttl, rdata, binary)
  end

  defp build_answer(domain, :A, ttl, rdata, _binary) do
    %{
      type: :A,
      ttl: ttl,
      domain: domain,
      addr: rdata |> :binary.bin_to_list() |> List.to_tuple()
    }
  end

  defp build_answer(domain, :NS, ttl, rdata, binary) do
    [host, ""] = extract_label(rdata, binary)

    %{
      type: :NS,
      ttl: ttl,
      domain: domain,
      host: host
    }
  end

  defp build_answer(domain, :CNAME, ttl, rdata, binary) do
    [host, ""] = extract_label(rdata, binary)

    %{
      type: :CNAME,
      ttl: ttl,
      domain: domain,
      host: host
    }
  end

  defp build_answer(domain, :MX, ttl, rdata, binary) do
    <<preference::16, rest::binary>> = rdata
    [exchange, ""] = extract_label(rest, binary)

    %{
      type: :MX,
      ttl: ttl,
      domain: domain,
      preference: preference,
      exchange: exchange
    }
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

  defp resolve_type(1), do: :A
  defp resolve_type(2), do: :NS
  defp resolve_type(5), do: :CNAME
  defp resolve_type(15), do: :MX
end
