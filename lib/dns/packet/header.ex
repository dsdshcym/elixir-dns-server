defmodule DNS.Packet.Header do
  defstruct id: nil,
            query_response: false,
            operation_code: 0,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: false,
            recursion_available: false,
            reserved: 0,
            response_code: 0,
            question_count: 0,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0

  @type t :: %__MODULE__{
          id: 0..65535,
          query_response: boolean(),
          operation_code: 0..15,
          authoritative_answer: boolean(),
          truncated_message: boolean(),
          recursion_desired: boolean(),
          recursion_available: boolean(),
          reserved: 0..7,
          response_code: 0..15,
          question_count: 0..65535,
          answer_count: 0..65535,
          authority_count: 0..65535,
          additional_count: 0..65535
        }

  def to_binary(%__MODULE__{} = header) do
    <<
      header.id::16,
      bool_to_int(header.query_response)::1,
      header.operation_code::4,
      bool_to_int(header.authoritative_answer)::1,
      bool_to_int(header.truncated_message)::1,
      bool_to_int(header.recursion_desired)::1,
      bool_to_int(header.recursion_available)::1,
      header.reserved::3,
      header.response_code::4,
      header.question_count::16,
      header.answer_count::16,
      header.authority_count::16,
      header.additional_count::16
    >>
  end

  defp bool_to_int(true), do: 1
  defp bool_to_int(false), do: 0
end
