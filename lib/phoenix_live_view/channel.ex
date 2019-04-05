defmodule Phoenix.LiveView.Channel do
  @moduledoc false
  use GenServer

  require Logger

  alias Phoenix.LiveView
  alias Phoenix.LiveView.{Socket, View, Diff}

  alias Phoenix.Socket.Message

  @prefix :phoenix

  def start_link({auth_payload, from, phx_socket}) do
    GenServer.start_link(__MODULE__, {auth_payload, from, phx_socket})
  end

  def ping(pid) do
    GenServer.call(pid, {@prefix, :ping})
  end

  @impl true
  def init(triplet) do
    send(self(), {:join, __MODULE__})
    {:ok, triplet}
  end

  @impl true
  def handle_info({:join, __MODULE__}, triplet) do
    join(triplet)
  end

  def handle_info({:DOWN, _, _, transport_pid, reason}, %{transport_pid: transport_pid} = state) do
    reason = if reason == :normal, do: {:shutdown, :closed}, else: reason
    {:stop, reason, state}
  end

  def handle_info({:DOWN, _, :process, parent, reason}, %{socket: %{parent_pid: parent}} = state) do
    send(state.transport_pid, {:socket_close, self(), reason})

    {:stop, reason, state}
  end

  def handle_info(
        {:DOWN, _ref, :process, maybe_child_pid, _reason} = msg,
        %{socket: socket} = state
      ) do
    case Map.fetch(state.children_pids, maybe_child_pid) do
      {:ok, id} ->
        new_pids = Map.delete(state.children_pids, maybe_child_pid)
        new_ids = Map.delete(state.children_ids, id)
        {:noreply, %{state | children_pids: new_pids, children_ids: new_ids}}

      :error ->
        handle_result(state, :info, socket, view_module(state).handle_info(msg, socket))
    end
  end

  def handle_info(%Message{topic: topic, event: "phx_leave"} = msg, %{topic: topic} = state) do
    reply(state, msg.ref, :ok, %{})

    {:stop, {:shutdown, :left}, state}
  end

  def handle_info(%Message{topic: topic, event: "event"} = msg, %{topic: topic} = state) do
    %{"value" => raw_val, "event" => event, "type" => type} = msg.payload
    val = decode(type, raw_val)
    result = view_module(state).handle_event(event, val, state.socket)
    handle_result(state, {:event, msg.ref}, state.socket, result)
  end

  def handle_info(msg, %{socket: socket} = state) do
    handle_result(state, :info, socket, view_module(state).handle_info(msg, socket))
  end

  @impl true
  def handle_call({@prefix, :ping}, _from, state) do
    {:reply, :ok, state}
  end

  def handle_call({@prefix, :child_mount, child_pid, view, id, assigned_new}, _from, state) do
    IO.inspect({:child_mount, view, id, assigned_new})
    assigns = Map.take(state.socket.assigns, assigned_new)
    {:reply, {:ok, assigns}, put_child(state, child_pid, view, id)}
  end

  def handle_call(msg, from, %{socket: socket} = state) do
    handle_result(state, :call, socket, view_module(state).handle_call(msg, from, socket))
  end

  @impl true
  def terminate(reason, %{socket: socket} = state) do
    view = view_module(state)

    if function_exported?(view, :terminate, 2) do
      view.terminate(reason, socket)
    else
      :ok
    end
  end

  def terminate(_reason, _state) do
    :ok
  end

  @impl true
  def code_change(old, %{socket: socket} = state, extra) do
    view = view_module(state)

    if function_exported?(view, :code_change, 3) do
      view.code_change(old, socket, extra)
    else
      {:ok, state}
    end
  end

  defp handle_result(state, {:event, ref}, %Socket{} = socket, {:noreply, %Socket{} = socket}) do
    {:noreply, ack_render(state, ref)}
  end

  defp handle_result(state, :call, %Socket{} = socket, {:reply, reply, %Socket{} = socket}) do
    {:reply, reply, state}
  end

  defp handle_result(state, _kind, %Socket{} = socket, {:noreply, %Socket{} = socket}) do
    {:noreply, state}
  end

  defp handle_result(state, :call, %Socket{} = _before, {:reply, reply, %Socket{} = new_socket}) do
    {new_state, rendered} = rerender(%{state | socket: new_socket})
    {:reply, reply, push_render(new_state, :call, rendered)}
  end

  defp handle_result(state, kind, %Socket{} = _before, {:noreply, %Socket{} = new_socket}) do
    {new_state, rendered} = rerender(%{state | socket: new_socket})
    {:noreply, push_render(new_state, kind, rendered)}
  end

  defp handle_result(
         state,
         _kind,
         _socket,
         {:stop, %Socket{stopped: {:redirect, %{to: to}}} = new_socket}
       ) do
    new_state = push_redirect(%{state | socket: new_socket}, to, View.get_flash(new_socket))
    send(state.transport_pid, {:socket_close, self(), :redirect})

    {:stop, {:shutdown, :redirect}, new_state}
  end

  defp handle_result(state, {:event, _}, _original_socket, result) do
    raise ArgumentError, """
    invalid noreply from #{inspect(view_module(state))}.handle_event/3 callback.

    Expected {:noreply, %Socket{}} | {:stop, reason, %Socket{}}. got: #{inspect(result)}
    """
  end

  defp view_module(%{socket: socket}), do: View.view(socket)

  defp decode("form", url_encoded) do
    Plug.Conn.Query.decode(url_encoded)
  end

  defp decode(_, value), do: value

  defp ack_render(state, ref) do
    reply(state, ref, :ok, %{})
    state
  end

  defp push_render(state, {:event, ref}, %LiveView.Rendered{} = rendered) do
    {new_state, diff} = render_diff(state, rendered)
    reply(state, ref, :ok, diff)
    new_state
  end

  defp push_render(state, kind, %LiveView.Rendered{} = rendered) when kind in [:info, :call] do
    {new_state, diff} = render_diff(state, rendered)
    push(new_state, "render", diff)
    new_state
  end

  defp push_redirect(%{socket: socket} = state, to, flash) do
    push(state, "redirect", %{to: to, flash: View.sign_flash(socket, flash)})
    state
  end

  defp render_diff(%{fingerprints: prints} = state, %LiveView.Rendered{} = rendered) do
    {diff, new_prints} = Diff.render(rendered, prints)
    {%{state | fingerprints: new_prints}, diff}
  end

  defp rerender(%{socket: socket, session: session} = state) do
    rendered = View.render(socket, session)
    {reset_changed(state, rendered.fingerprint), rendered}
  end

  defp reset_changed(%{socket: socket} = state, root_print) do
    new_socket =
      socket
      |> View.clear_changed()
      |> View.put_root(root_print)

    %{state | socket: new_socket}
  end

  defp log_mount(%Phoenix.Socket{private: %{log_join: false}}, _), do: :noop
  defp log_mount(%Phoenix.Socket{private: %{log_join: level}}, func), do: Logger.log(level, func)
  defp log_mount(%Phoenix.Socket{private: %{}}, func), do: Logger.log(:debug, func)

  defp reply(state, ref, status, payload) do
    reply_ref = {state.transport_pid, state.serializer, state.topic, ref, state.join_ref}
    Phoenix.Channel.reply(reply_ref, {status, payload})
  end

  defp push(state, event, payload) do
    message = %Message{topic: state.topic, event: event, payload: payload}
    send(state.transport_pid, state.serializer.encode!(message))
    :ok
  end

  ## Join

  defp join({%{"session" => session_token} = params, from, phx_socket}) do
    case View.verify_session(phx_socket.endpoint, session_token, params["static"]) do
      {:ok, %{id: id, view: view, parent_pid: parent, session: user_session, assigned_new: new}} ->
        verified_join(view, id, parent, new, user_session, from, phx_socket)

      {:error, reason} ->
        log_mount(phx_socket, fn ->
          "Mounting #{phx_socket.topic} failed while verifying session with: #{inspect(reason)}"
        end)

        GenServer.reply(from, {:error, %{reason: "badsession"}})
        {:stop, :shutdown, :no_state}
    end
  end

  defp join({%{}, from, phx_socket}) do
    log_mount(phx_socket, fn ->
      "Mounting #{phx_socket.topic} failed because no session was provided"
    end)

    GenServer.reply(from, %{reason: "nosession"})
    :ignore
  end

  defp verified_join(
         view,
         id,
         parent,
         assigned_new,
         user_session,
         from,
         %Phoenix.Socket{} = phx_socket
       ) do
    Process.monitor(phx_socket.transport_pid)

    lv_socket =
      phx_socket.endpoint
      |> View.build_socket(%{
        connected?: true,
        parent_pid: parent,
        view: view,
        id: id
      }, %{})
      |> monitor_parent(assigned_new)

    case view.mount(user_session, lv_socket) do
      {:ok, %Socket{} = lv_socket} ->
        {state, rendered} =
          lv_socket
          |> post_mount_prune()
          |> build_state(phx_socket, user_session)
          |> rerender()

        {new_state, rendered_diff} = render_diff(state, rendered)

        GenServer.reply(from, {:ok, %{rendered: rendered_diff}})
        {:noreply, new_state}

      {:stop, %Socket{stopped: {:redirect, %{to: to}}}} ->
        log_mount(phx_socket, fn -> "Redirecting #{inspect(view)} #{id} to: #{inspect(to)}" end)
        GenServer.reply(from, {:error, %{redirect: to}})
        {:stop, :shutdown, :no_state}

      other ->
        View.raise_invalid_mount(other, view)
    end
  end

  defp build_state(%Socket{} = lv_socket, %Phoenix.Socket{} = phx_socket, session) do
    %{
      socket: lv_socket,
      session: session,
      fingerprints: nil,
      serializer: phx_socket.serializer,
      topic: phx_socket.topic,
      transport_pid: phx_socket.transport_pid,
      join_ref: phx_socket.join_ref,
      children_pids: %{},
      children_ids: %{}
    }
  end

  defp monitor_parent(%Socket{parent_pid: nil} = socket, _assigned_new), do: socket

  defp monitor_parent(%Socket{parent_pid: parent, id: id} = socket, assigned_new) do
    _ref = Process.monitor(parent)

    {:ok, values} =
      GenServer.call(parent, {@prefix, :child_mount, self(), socket.view, id, assigned_new})

    put_parent_assigns(socket, values)
  end

  defp put_child(%{socket: %Socket{view: parent}} = state, child_pid, view, id) do
    case Map.fetch(state.children_ids, id) do
      {:ok, existing_pid} ->
        raise RuntimeError, """
        unable to start child #{inspect(view)} under duplicate name for parent #{inspect(parent)}.
        A child LiveView #{inspect(existing_pid)} is already running under the ID #{id}.

        To render multiple LiveView children of the same module, a
        child_id option must be provided per live_render call. For example:

            <%= live_render @socket, #{inspect(view)}, child_id: 1 %>
            <%= live_render @socket, #{inspect(view)}, child_id: 2 %>
        """

      :error ->
        _ref = Process.monitor(child_pid)

        %{
          state
          | children_pids: Map.put(state.children_pids, child_pid, id),
            children_ids: Map.put(state.children_ids, id, child_pid)
        }
    end
  end

  defp post_mount_prune(%Socket{} = socket) do
    %Socket{socket | private: Map.delete(socket.private, :parent_assigns)}
  end

  defp put_parent_assigns(socket, values) do
    %Socket{socket | private: Map.put(socket.private, :parent_assigns, values)}
  end
end
