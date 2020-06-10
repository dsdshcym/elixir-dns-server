defmodule DNS.Packet.ResourceRecord do
  def to_binary(records) when is_list(records) do
    records
    |> Enum.map(&to_binary/1)
    |> Enum.join()
  end

  def to_binary(record) do
    rdata = extract_rdata(record)
    rdlen = String.length(rdata)

    <<
      to_label(record.domain)::binary,
      to_enum(record.type)::16,
      0::16,
      record.ttl::16,
      rdlen::16,
      rdata::binary
    >>
  end

  defp to_label(binary) do
    (binary
     |> String.split(".")
     |> Enum.map(&[String.length(&1), &1])
     |> IO.iodata_to_binary()) <>
      <<0>>
  end

  defp to_enum(:A), do: 1
  defp to_enum(:NS), do: 2
  defp to_enum(:CNAME), do: 5
  defp to_enum(:MX), do: 15
  defp to_enum(:AAAA), do: 28

  defp extract_rdata(%{type: :A, addr: addr}),
    do: addr |> Tuple.to_list() |> IO.iodata_to_binary()

  defp extract_rdata(%{type: :NS, host: host}) do
    to_label(host)
  end

  defp extract_rdata(%{type: :CNAME, host: host}) do
    to_label(host)
  end

  defp extract_rdata(%{type: :MX, preference: preference, exchange: exchange}) do
    <<preference::16, to_label(exchange)::binary>>
  end

  defp extract_rdata(%{type: :AAAA, addr: addr}),
    do: addr |> Tuple.to_list() |> Enum.map(&<<&1::16>>) |> IO.iodata_to_binary()
end
