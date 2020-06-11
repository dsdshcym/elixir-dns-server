defmodule DNS.ServerTest do
  use ExUnit.Case, async: true

  alias DNS.Server

  defmodule GoogleDNS do
    @google_dns {{8, 8, 8, 8}, 53}

    def query(domain) do
      binary = domain |> DNS.Packet.new_query() |> DNS.Packet.to_binary()

      server = Socket.UDP.open!(2053)
      Socket.Datagram.send!(server, binary, @google_dns)
      {response, @google_dns} = Socket.Datagram.recv!(server)
      Socket.close!(server)

      DNS.Packet.parse(response)
    end
  end

  describe "returns the same result as GoogleDNS" do
    test "zhihu.com" do
      %{answers: [%{addr: expected}]} = GoogleDNS.query("zhihu.com")

      {:ok, server} = Server.start()
      {:ok, %{answers: [%{addr: actual}]}} = Server.recursive_lookup(server, "zhihu.com")
      Server.stop(server)

      assert expected == actual
    end
  end

  describe "recursive_lookup/2" do
    test "zhihu.com" do
      {:ok, server} = Server.start()

      {:ok, response} = Server.recursive_lookup(server, "zhihu.com")

      assert %{answers: [%{addr: {103, 41, 167, 234}}]} = response

      Server.stop(server)
    end

    test "handle queries concurrently" do
      {:ok, server} = Server.start()

      assert [
               {:ok, {:ok, %{answers: [%{domain: "zhihu.com"} | _]}}},
               {:ok, {:ok, %{answers: [%{domain: "yahoo.com"} | _]}}},
               {:ok, {:ok, %{answers: [%{domain: "baidu.com"} | _]}}} | _
             ] =
               ["zhihu.com", "yahoo.com", "baidu.com"]
               |> Task.async_stream(&Server.recursive_lookup(server, &1))
               |> Enum.to_list()

      Server.stop(server)
    end
  end
end
