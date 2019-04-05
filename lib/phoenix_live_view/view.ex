defmodule Phoenix.LiveView.View do
  @moduledoc false
  import Phoenix.HTML, only: [sigil_E: 2]

  alias Phoenix.LiveView
  alias Phoenix.LiveView.Socket

  @max_session_age 1_209_600

  @salt_length 8

  @doc """
  Clears the changes from the socket assigns.
  """
  def clear_changed(%Socket{} = socket) do
    %Socket{socket | changed: nil}
  end

  @doc """
  Returns the socket's flash messages.
  """
  def get_flash(%Socket{private: private}) do
    private[:flash]
  end

  @doc """
  Puts the root fingerprint.
  """
  def put_root(%Socket{} = socket, root_fingerprint) do
    %Socket{socket | root_fingerprint: root_fingerprint}
  end

  @doc """
  Returns the browser's DOM id for the socket's view.
  """
  def dom_id(%Socket{id: id}), do: id

  @doc """
  Returns the browser's DOM id for the nested socket.
  """
  def child_dom_id(%Socket{id: parent_id}, child_view, nil = _child_id) do
    parent_id <> inspect(child_view)
  end
  def child_dom_id(%Socket{id: parent_id}, child_view, child_id) do
    parent_id <> inspect(child_view) <> to_string(child_id)
  end

  @doc """
  Returns the socket's LiveView module.
  """
  def view(%Socket{view: view}), do: view

  @doc """
  Returns true if the socket is connected.
  """
  def connected?(%Socket{connected?: true}), do: true
  def connected?(%Socket{connected?: false}), do: false

  @doc """
  Builds a `%Phoenix.LiveViewSocket{}`.
  """
  def build_socket(endpoint, %{} = opts, parent_assigns) when is_atom(endpoint) do
    opts = normalize_opts!(opts)

    %Socket{
      id: Map.get_lazy(opts, :id, fn -> random_id() end),
      endpoint: endpoint,
      parent_pid: opts[:parent_pid],
      view: Map.fetch!(opts, :view),
      assigns: Map.get(opts, :assigns, %{}),
      connected?: Map.get(opts, :connected?, false),
      private: %{parent_assigns: parent_assigns, assigned_new: []}
    }
  end

  @doc """
  Builds a nested child `%Phoenix.LiveViewSocket{}`.
  """
  def build_nested_socket(%Socket{endpoint: endpoint} = parent, child_id, %{view: view} = opts) do
    id = child_dom_id(parent, view, child_id)
    nested_opts = Map.merge(opts, %{id: id, parent_pid: self()})
    build_socket(endpoint, nested_opts, parent.assigns)
  end

  @doc """
  Annotates the socket for redirect.
  """
  def put_redirect(%Socket{stopped: nil} = socket, to) do
    %Socket{socket | stopped: {:redirect, %{to: to}}}
  end
  def put_redirect(%Socket{stopped: reason} = _socket, _to) do
    raise ArgumentError, "socket already prepared to stop for #{inspect(reason)}"
  end

  @doc """
  Renders the view into a `%Phoenix.LiveView.Rendered{}` struct.
  """
  def render(%Socket{} = socket, session) do
    view = view(socket)
    assigns = Map.merge(socket.assigns, %{session: session, socket: socket})

    case view.render(assigns) do
      %Phoenix.LiveView.Rendered{} = rendered ->
        rendered

      other ->
        raise RuntimeError, """
        expected #{inspect(view)}.render/1 to return a %Phoenix.LiveView.Rendered{} struct

        Ensure your render function uses ~L, or your eex template uses the .leex extension.

        Got:

            #{inspect(other)}

        """
    end
  end

  @doc """
  Verifies the session token.

  Returns the decoded map of session data or an error.

  # TODO FIX DOCS

  ## Examples

      iex> verify_session(AppWeb.Endpoint, encoded_token_string)
      {:ok, %{} = decoeded_session}

      iex> verify_session(AppWeb.Endpoint, "bad token")
      {:error, :invalid}

      iex> verify_session(AppWeb.Endpoint, "expired")
      {:error, :expired}
  """
  def verify_session(endpoint, session_token, static_token) do
    with {:ok, session} <- verify_token(endpoint, session_token),
         {:ok, static} <- verify_static_token(endpoint, static_token) do

      {:ok, Map.merge(session, static)}
    end
  end
  defp verify_static_token(_endpoint, nil), do: {:ok, %{assigned_new: []}}
  defp verify_static_token(endpoint, token), do: verify_token(endpoint, token)
  defp verify_token(endpoint, token) do
    case Phoenix.Token.verify(endpoint, salt(endpoint), token, max_age: @max_session_age) do
      {:ok, encoded_term} ->
        term = encoded_term |> Base.decode64!() |> :erlang.binary_to_term()
        {:ok, term}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Signs the socket's flash into a token if it has been set.
  """
  def sign_flash(%Socket{}, nil), do: nil

  def sign_flash(%Socket{endpoint: endpoint}, %{} = flash) do
    LiveView.Flash.sign_token(endpoint, salt(endpoint), flash)
  end

  @doc """
  Raises error message for invalid view mount.
  """
  def raise_invalid_mount(other, view) do
    raise ArgumentError, """
    invalid result returned from #{inspect(view)}.mount/2.

    Expected {:ok, socket}, got: #{inspect(other)}
    """
  end

  @doc """
  Renders a live view without spawning a LiveView server.

  * `conn` - the Plug.Conn struct form the HTTP request
  * `view` - the LiveView module

  ## Options

    * `:session` - the required map of session data
    * `:container` - the optional tuple for the HTML tag and DOM attributes to
      be used for the LiveView container. For example: `{:li, style: "color: blue;"}`
  """
  def static_render(%Plug.Conn{} = conn, view, opts) do
    session = Keyword.fetch!(opts, :session)
    {tag, extended_attrs} = opts[:container] || {:div, []}

    case static_mount(conn, view, session) do
      {:ok, socket, session_token} ->
        attrs = [
          {:id, dom_id(socket)},
          {:data,
            phx_view: inspect(view),
            phx_session: session_token,
          } | extended_attrs
        ]

        html = ~E"""
        <%= Phoenix.HTML.Tag.content_tag(tag, attrs) do %>
          <%= render(socket, session) %>
        <% end %>
        <div class="phx-loader"></div>
        """
        {:ok, html}

      {:stop, reason} -> {:stop, reason}
    end
  catch
    :throw, {:stop, reason} -> {:stop, reason}
  end

  @doc """
  Renders a nested live view without spawning a server.

  * `parent` - the parent `%Phoenix.LiveView.Socket{}`
  * `view` - the child LiveView module

  Accepts the same options as `static_render/3`.
  """
  def nested_static_render(%Socket{} = parent, view, opts) do
    session = Keyword.fetch!(opts, :session)
    {_tag, _attrs} = container = opts[:container] || {:div, []}
    child_id = opts[:child_id]

    if connected?(parent) do
      connected_nested_static_render(parent, view, session, container, child_id)
    else
      disconnected_nested_static_render(parent, view, session, container, child_id)
    end
  end

  def configured_signing_salt!(endpoint) when is_atom(endpoint) do
    endpoint.config(:live_view)[:signing_salt] ||
      raise ArgumentError, """
      no signing salt found for #{inspect(endpoint)}.

      Add the following LiveView configuration to your config/config.exs:

          config :my_app, MyAppWeb.Endpoint,
              ...,
              live_view: [signing_salt: "#{random_signing_salt()}"]

      """
  end

  defp disconnected_nested_static_render(parent, view, session, container, child_id) do
    {tag, extended_attrs} = container

    case nested_static_mount(parent, view, session, child_id) do
      {:ok, socket, static_token} ->
        attrs = [
          {:id, socket.id},
          {:data,
            phx_view: inspect(view),
            phx_session: "",
            phx_static: static_token,
            phx_parent_id: parent.id
          } | extended_attrs
        ]

       html = ~E"""
        <%= Phoenix.HTML.Tag.content_tag(tag, attrs) do %>
          <%= render(socket, session) %>
        <% end %>
        <div class="phx-loader"></div>
        """
        {:ok, html}


      {:stop, reason} -> {:stop, reason}
    end
  end

  defp connected_nested_static_render(parent, view, session, container, child_id) do
    {tag, extended_attrs} = container
    socket = build_nested_socket(parent, child_id, %{view: view})
    session_token = sign_child_session(socket, session)

    attrs = [
      {:id, socket.id},
      {:data,
        phx_parent_id: dom_id(parent),
        phx_view: inspect(view),
        phx_session: session_token,
        phx_static: "",
      } | extended_attrs
    ]

    html = ~E"""
    <%= Phoenix.HTML.Tag.content_tag(tag, "", attrs) %>
    <div class="phx-loader"></div>
    """

    {:ok, html}
  end

  defp nested_static_mount(%Socket{} = parent, view, session, child_id) do
    socket = build_nested_socket(parent, child_id, %{view: view})

    session
    |> view.mount(socket)
    |> case do
      {:ok, %Socket{} = new_socket} ->
        {:ok, new_socket, sign_static_token(new_socket)}

      {:stop, socket} ->
        {:stop, socket.stopped}

      other ->
        raise_invalid_mount(other, view)
    end
  end

  defp static_mount(%Plug.Conn{} = conn, view, session) do
    conn
    |> Phoenix.Controller.endpoint_module()
    |> build_socket(%{view: view}, conn.assigns)
    |> do_static_mount(view, session)
  end

  defp do_static_mount(socket, view, session) do
    session
    |> view.mount(socket)
    |> case do
      {:ok, %Socket{} = new_socket} ->
        session_token = sign_root_session(socket, session)

        {:ok, new_socket, session_token}

      {:stop, socket} ->
        {:stop, socket.stopped}

      other ->
        raise_invalid_mount(other, view)
    end
  end

  defp sign_root_session(%Socket{id: dom_id} = socket, session) do
    token =
      sign_token(socket.endpoint, salt(socket), %{
        id: dom_id,
        view: view(socket),
        parent_pid: nil,
        session: session,
      })

    session_vsn(session) <> ":" <> token
  end

  defp sign_child_session(%Socket{id: dom_id} = socket, session) do
    token =
      sign_token(socket.endpoint, salt(socket), %{
        id: dom_id,
        view: view(socket),
        parent_pid: self(),
        session: session,
      })

    session_vsn(session) <> ":" <> token
  end

  defp sign_static_token(%Socket{} = socket) do
    IO.inspect({:signing, socket.view, assigned_new(socket)})
    sign_token(socket.endpoint, salt(socket), %{
      assigned_new: assigned_new(socket),
    })
  end

  defp session_vsn(session) do
    session |> :erlang.term_to_binary() |> :erlang.md5() |> Base.encode64()
  end

  defp salt(%Socket{endpoint: endpoint}) do
    salt(endpoint)
  end

  defp salt(endpoint) when is_atom(endpoint) do
    configured_signing_salt!(endpoint)
  end

  defp random_signing_salt do
    @salt_length
    |> :crypto.strong_rand_bytes()
    |> Base.encode64()
    |> binary_part(0, @salt_length)
  end

  defp random_id, do: "phx-" <> Base.encode64(:crypto.strong_rand_bytes(8))

  defp sign_token(endpoint, salt, data) do
    encoded_data = data |> :erlang.term_to_binary() |> Base.encode64()
    Phoenix.Token.sign(endpoint, salt, encoded_data)
  end
  defp normalize_opts!(opts) do
    valid_keys = Map.keys(%Socket{})
    provided_keys = Map.keys(opts)

    if provided_keys -- valid_keys != [],
      do:
        raise(ArgumentError, """
        invalid socket keys. Expected keys #{inspect(valid_keys)}, got #{inspect(provided_keys)}
        """)

    opts
  end

  defp assigned_new(socket), do: socket.private.assigned_new
end
