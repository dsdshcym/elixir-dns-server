defmodule DNS.Packet.Question do
  defstruct name: nil, type: nil
  @type t :: %__MODULE__{name: binary(), type: atom()}
end
