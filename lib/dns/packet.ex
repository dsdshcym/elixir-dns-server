defmodule DNS.Packet do
  alias DNS.Packet.Header
  alias DNS.Packet.Question
  alias DNS.Packet.ResourceRecord

  defstruct header: %Header{}, questions: [], answers: [], authorities: [], additionals: []

  @type t :: %__MODULE__{
          header: Header.t(),
          questions: list(Question.t()),
          answers: list(),
          authorities: list(),
          additionals: list()
        }

  @spec new_query(binary()) :: t()
  def new_query(domain) do
    %__MODULE__{
      header: %Header{
        # TODO: pass id as an argument
        id: Enum.random(0..65535),
        query_response: false,
        operation_code: 0,
        question_count: 1,
        recursion_desired: false,
        authoritative_answer: false,
        truncated_message: false,
        recursion_available: false,
        reserved: 0,
        response_code: 0,
        answer_count: 0,
        authority_count: 0,
        additional_count: 0
      },
      questions: [%Question{name: domain, type: :A}]
    }
  end

  @spec to_binary(t()) :: binary()
  def to_binary(%__MODULE__{} = packet) do
    Header.to_binary(packet.header) <>
      Question.to_binary(packet.questions) <>
      ResourceRecord.to_binary(packet.answers) <>
      ResourceRecord.to_binary(packet.authorities) <>
      ResourceRecord.to_binary(packet.additionals)
  end

  @spec parse(binary()) :: t()
  def parse(binary) do
    {header, rest} = parse_header(binary)

    {:ok, [questions, answers, authorities, additionals], ""} =
      sequence([
        repeat(question_parser(binary), header.question_count),
        repeat(resource_record_parser(binary), header.answer_count),
        repeat(resource_record_parser(binary), header.authority_count),
        repeat(resource_record_parser(binary), header.additional_count)
      ]).(rest)

    %__MODULE__{
      header: header,
      questions: questions,
      answers: answers,
      authorities: authorities,
      additionals: additionals
    }
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
    {
      %Header{
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
    }
  end

  defp sequence(parsers) do
    fn input ->
      case parsers do
        [] ->
          {:ok, [], input}

        [first_parser | other_parsers] ->
          with {:ok, first_term, rest} <- first_parser.(input),
               {:ok, other_terms, rest} <- sequence(other_parsers).(rest),
               do: {:ok, [first_term | other_terms], rest}
      end
    end
  end

  defp repeat(parser, count) do
    parser
    |> List.duplicate(count)
    |> sequence()
  end

  defp question_parser(binary) do
    fn input ->
      {label, rest} = extract_label(input, binary)
      <<type_enum::size(16), _class::size(16), rest::binary>> = rest
      {:ok, build_question(label, type_enum), rest}
    end
  end

  defp build_question(name, type_enum) when is_number(type_enum) do
    build_question(name, resolve_type(type_enum))
  end

  defp build_question(name, type) when is_atom(type) do
    %Question{name: name, type: type}
  end

  defp resource_record_parser(binary) do
    fn input ->
      {label, rest} = extract_label(input, binary, [])

      <<type_enum::size(16), _class::size(16), ttl::size(32), len::size(16),
        rdata::bytes-size(len), rest::binary>> = rest

      resource_record = build_resource_record(label, type_enum, ttl, rdata, binary)

      {:ok, resource_record, rest}
    end
  end

  defp build_resource_record(domain, type_enum, ttl, rdata, binary) when is_number(type_enum) do
    build_resource_record(domain, resolve_type(type_enum), ttl, rdata, binary)
  end

  defp build_resource_record(domain, :A, ttl, rdata, _binary) do
    %{
      type: :A,
      ttl: ttl,
      domain: domain,
      addr: rdata |> :binary.bin_to_list() |> List.to_tuple()
    }
  end

  defp build_resource_record(domain, :NS, ttl, rdata, binary) do
    {host, ""} = extract_label(rdata, binary)

    %{
      type: :NS,
      ttl: ttl,
      domain: domain,
      host: host
    }
  end

  defp build_resource_record(domain, :CNAME, ttl, rdata, binary) do
    {host, ""} = extract_label(rdata, binary)

    %{
      type: :CNAME,
      ttl: ttl,
      domain: domain,
      host: host
    }
  end

  defp build_resource_record(domain, :MX, ttl, rdata, binary) do
    <<preference::16, rest::binary>> = rdata
    {exchange, ""} = extract_label(rest, binary)

    %{
      type: :MX,
      ttl: ttl,
      domain: domain,
      preference: preference,
      exchange: exchange
    }
  end

  defp build_resource_record(domain, :AAAA, ttl, rdata, _binary) do
    ipv6 =
      for(<<part::16 <- rdata>>, do: part)
      |> List.to_tuple()

    %{
      type: :AAAA,
      ttl: ttl,
      domain: domain,
      addr: ipv6
    }
  end

  defp build_resource_record(domain, _, ttl, rdata, _binary) do
    %{
      type: :UNKNOWN,
      ttl: ttl,
      domain: domain,
      rdata: rdata
    }
  end

  defp extract_label(rest, binary, label_parts \\ [])

  defp extract_label(<<1::size(1), 1::size(1), pos::size(14), rest::binary>>, binary, label_parts) do
    <<_::bytes-size(pos), jump::bytes>> = binary
    {label, _} = extract_label(jump, binary)

    label_parts = [label | label_parts]
    {label_parts |> Enum.reverse() |> Enum.join("."), rest}
  end

  defp extract_label(<<0, rest::binary>>, _binary, label_parts) do
    {label_parts |> Enum.reverse() |> Enum.join("."), rest}
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
  defp resolve_type(28), do: :AAAA
  defp resolve_type(_), do: :UNKNOWN
end
