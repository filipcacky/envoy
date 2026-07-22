QUIC listeners now create the connection ID generator factory and apply its packet-routing socket
option in ``ActiveUdpListenerFactory::initializeSocketDependentState``. This runs after the listen
sockets are bound, or duplicated after an LDS update or the hotrestart RPC.
This behavior can reverted by setting runtime guard
``envoy.restart_features.quic_listener_factory_deferred_socket_option_init`` to ``false``.
