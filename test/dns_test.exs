defmodule DNSTest do
  use ExUnit.Case
  doctest DNS

  test "greets the world" do
    assert DNS.hello() == :world
  end
end
