defmodule Phoenix.LiveView.UploadChannel do
  @moduledoc false
  use GenServer

  require Logger

  alias Phoenix.LiveView
  alias Phoenix.LiveView.{Socket, View, Diff}

  alias Phoenix.LiveView.UploadFrame

  def start_link({auth_payload, from, phx_socket}) do
    GenServer.start_link(__MODULE__, {auth_payload, from, phx_socket})
  end

  @impl true
  def init(triplet) do
    send(self(), {:join, __MODULE__})
    {:ok, triplet}
  end

  @impl true
  def handle_info({:join, __MODULE__}, {_, from, phx_socket} = state) do
    GenServer.reply(from, {:ok, %{}})
    {:noreply, phx_socket}
  end

  def handle_info(%Phoenix.Socket.Message{topic: topic, payload: payload, ref: ref} = msg, state) do
    reply_ref = {state.transport_pid, state.serializer, state.topic, ref, state.join_ref}
    Phoenix.Channel.reply(reply_ref, {:ok, %{file_ref: "1"}})
    {:noreply, Phoenix.Socket.assign(state, :upload, payload)}
  end

  def handle_info(_, state) do
    {:noreply, state}
  end

  @impl true
  def handle_call({:get_file, ref}, _reply, %{assigns: %{upload: upload}} = state) do
    # TODO: change this upload mechanism?
    path = Plug.Upload.random_file!("multipart")
    File.write(path, upload)
    {:reply, {:ok, path}, %{state | assigns: %{}}}
  end
end
