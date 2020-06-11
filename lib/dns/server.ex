defmodule DNS.Server do
  @root_dns {198, 41, 0, 4}
  @default_dns_port 53

  use GenServer

  def start do
    GenServer.start(__MODULE__, [])
  end

  def stop(server) do
    GenServer.stop(server)
  end

  def recursive_lookup(server, domain) do
    GenServer.call(server, {:recursive_lookup, domain})
  end

  @impl true
  def init(_) do
    {:ok, udp_server} = Socket.UDP.open(2053, mode: :active)

    {:ok, %{udp_server: udp_server, callees: %{}}}
  end

  @impl true
  def handle_call({:recursive_lookup, domain}, from, %{udp_server: udp_server} = state) do
    query =
      domain
      |> DNS.Packet.new_query()

    binary =
      query
      |> DNS.Packet.to_binary()

    :ok = Socket.Datagram.send(udp_server, binary, {@root_dns, @default_dns_port})

    {:noreply, put_in(state.callees[query.header.id], %{from: from, query: query})}
  end

  @impl true
  def handle_info(
        {:udp, udp_server, _, @default_dns_port, response},
        %{udp_server: udp_server} = state
      ) do
    response = DNS.Packet.parse(response)

    {callee, new_state} = pop_in(state.callees[response.header.id])

    if response.header.answer_count > 0 do
      GenServer.reply(callee.from, {:ok, response})

      {:noreply, new_state}
    else
      [%{host: next_dns_server_domain} | _] = response.authorities

      %{addr: next_dns_server_ip} =
        response.additionals
        |> Enum.find(&match?(%{domain: ^next_dns_server_domain, type: :A}, &1))

      :ok =
        Socket.Datagram.send(
          udp_server,
          DNS.Packet.to_binary(callee.query),
          {next_dns_server_ip, @default_dns_port}
        )

      {:noreply, put_in(new_state.callees[response.header.id], callee)}
    end
  end
end
