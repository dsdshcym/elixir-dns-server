defmodule DNS.Packet.Question do
  defstruct name: nil, type: nil
  @type t :: %__MODULE__{name: binary(), type: atom()}

  def to_binary(questions) when is_list(questions) do
    questions
    |> Enum.map(&to_binary/1)
    |> Enum.join()
  end

  def to_binary(%__MODULE__{} = question) do
    to_label(question.name) <>
      to_type(question.type) <>
      <<1::16>>
  end

  defp to_label(binary) do
    (binary
     |> String.split(".")
     |> Enum.map(&[String.length(&1), &1])
     |> IO.iodata_to_binary()) <>
      <<0>>
  end

  defp to_type(:A), do: <<1::16>>
end
