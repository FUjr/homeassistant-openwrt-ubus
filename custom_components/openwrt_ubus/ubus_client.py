"""Enhanced Ubus client with proper SSL handling."""

from __future__ import annotations

import asyncio
import logging
import ssl
from typing import Optional

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector

from .Ubus.interface import Ubus
from .Ubus.const import API_DEF_TIMEOUT

_LOGGER = logging.getLogger(__name__)


class EnhancedUbusClient(Ubus):
    """Enhanced Ubus client with proper SSL handling."""

    def __init__(
        self,
        host,
        username,
        password,
        session=None,
        timeout=API_DEF_TIMEOUT,
        verify=True,
        cert_file=None,
    ):
        """Initialize enhanced Ubus client."""
        self.use_custom_session = False
        self._custom_session: Optional[ClientSession] = None
        self._ssl_configured = False
        self._ssl_verify = verify
        self._ssl_cert_file = cert_file

        # Use provided session (from Home Assistant) or create basic one
        # SSL configuration will be done asynchronously when needed
        if session is None:
            _LOGGER.warning("No session provided, creating basic session")
            # Create a basic session without SSL configuration for now
            self.use_custom_session = True
            timeout_obj = ClientTimeout(total=timeout, connect=10)
            self._custom_session = ClientSession(timeout=timeout_obj)
            session = self._custom_session
        else:
            _LOGGER.debug("Using provided session")

        super().__init__(host, username, password, session, timeout, verify)

        # Store SSL settings
        self.cert_file = cert_file

    async def _ensure_ssl_configured(self):
        """Ensure SSL context is configured asynchronously."""
        if self._ssl_configured:
            # SSL already configured
            return

        # Always configure SSL for HTTPS connections
        # Even when verify=False, we need to create an SSL context that disables verification
        _LOGGER.debug("Configuring SSL context - verify=%s, cert_file=%s",
                     self._ssl_verify, self._ssl_cert_file)

        try:
            # Run SSL context creation in thread pool to avoid blocking
            ssl_context = await asyncio.get_event_loop().run_in_executor(
                None, self._create_ssl_context_sync, self._ssl_verify, self._ssl_cert_file
            )

            if ssl_context:
                # Create new session with SSL context
                await self._replace_session_with_ssl(ssl_context)
                self._ssl_configured = True
                _LOGGER.info("SSL context configured asynchronously (verify=%s, has_cert=%s)",
                           self._ssl_verify, bool(self._ssl_cert_file))
            else:
                _LOGGER.warning("Failed to create SSL context, continuing with default session")

        except Exception as exc:
            _LOGGER.error("Failed to configure SSL context: %s", exc)
            _LOGGER.error("SSL configuration error - type: %s, message: %s", type(exc).__name__, str(exc))
            _LOGGER.debug("SSL configuration error details", exc_info=True)
            # Continue with existing session without SSL configuration

    def _create_ssl_context_sync(self, verify: bool, cert_file: Optional[str]) -> Optional[ssl.SSLContext]:
        """Create SSL context synchronously (runs in thread pool)."""
        try:
            ssl_context = ssl.create_default_context()

            if not verify:
                # Disable SSL verification for unsigned certificates
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                _LOGGER.info("SSL verification disabled for unsigned certificates - check_hostname=False, verify_mode=CERT_NONE")
            else:
                _LOGGER.info("SSL verification enabled - using default certificate verification")

            if cert_file:
                try:
                    ssl_context.load_cert_chain(cert_file)
                    _LOGGER.debug("Loaded custom certificate from %s", cert_file)
                except Exception as exc:
                    _LOGGER.error("Failed to load certificate %s: %s", cert_file, exc)
                    return None

            _LOGGER.debug("SSL context created successfully - verify=%s, check_hostname=%s, verify_mode=%s",
                         verify, ssl_context.check_hostname, ssl_context.verify_mode)
            return ssl_context
        except Exception as exc:
            _LOGGER.error("Error creating SSL context: %s", exc)
            return None

    async def _replace_session_with_ssl(self, ssl_context: ssl.SSLContext):
        """Replace current session with SSL-configured session."""
        if self._custom_session and not self._custom_session.closed:
            old_session = self._custom_session

            # Create new session with SSL context
            connector = TCPConnector(ssl=ssl_context)
            timeout_obj = ClientTimeout(total=self.timeout, connect=10)
            new_session = ClientSession(connector=connector, timeout=timeout_obj)

            # Replace session
            self._custom_session = new_session
            self.session = new_session

            # Close old session
            await old_session.close()
            _LOGGER.debug("Replaced session with SSL-configured session")

    async def connect(self):
        """Connect to OpenWrt device with SSL configuration."""
        _LOGGER.debug("EnhancedUbusClient.connect() called - ensuring SSL configuration")
        _LOGGER.debug("SSL settings before configuration: verify=%s, cert_file=%s, ssl_configured=%s",
                     self._ssl_verify, self._ssl_cert_file, self._ssl_configured)

        # Ensure SSL is configured before connecting
        await self._ensure_ssl_configured()

        _LOGGER.debug("SSL configuration completed, calling parent connect method")
        # Call parent connect method
        return await super().connect()

    async def close(self):
        """Close the session, including custom sessions if created."""
        await super().close()

        if self._custom_session and not self._custom_session.closed:
            await self._custom_session.close()
            self._custom_session = None
            _LOGGER.debug("Closed custom SSL session")

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()


def create_enhanced_ubus_client(
    host: str,
    username: str,
    password: str,
    session=None,
    timeout: int = 30,
    verify_ssl: bool = False,
    cert_file: Optional[str] = None
) -> EnhancedUbusClient:
    """Create an enhanced Ubus client with proper SSL handling.

    Args:
        host: OpenWrt device host
        username: Username for authentication
        password: Password for authentication
        session: Existing aiohttp session (optional)
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        cert_file: Path to custom certificate file

    Returns:
        Enhanced Ubus client instance
    """
    return EnhancedUbusClient(
        host=host,
        username=username,
        password=password,
        session=session,
        timeout=timeout,
        verify=verify_ssl,
        cert_file=cert_file
    )


class EnhancedExtendedUbusClient:
    """Wrapper for ExtendedUbus with enhanced SSL handling."""

    def __init__(self, host, username, password, session=None, timeout=30, verify=True, cert_file=None):
        """Initialize enhanced extended ubus client."""
        self.base_client = create_enhanced_ubus_client(
            host, username, password, session, timeout, verify, cert_file
        )
        self._extended_ubus = None

    @property
    def session_id(self):
        """Get session ID."""
        return self.base_client.session_id

    async def connect(self):
        """Connect to OpenWrt device."""
        # Ensure SSL is configured before connecting
        await self.base_client._ensure_ssl_configured()

        result = await self.base_client.connect()
        # Create ExtendedUbus instance using the base client's session
        from .extended_ubus import ExtendedUbus
        self._extended_ubus = ExtendedUbus(
            self.base_client.host,
            self.base_client.username,
            self.base_client.password,
            session=self.base_client.session,
            timeout=self.base_client.timeout,
            verify=self.base_client.verify,
            cert_file=self.base_client.cert_file
        )
        self._extended_ubus.session_id = result
        return result

    async def close(self):
        """Close the client."""
        await self.base_client.close()

    def __getattr__(self, name):
        """Delegate method calls to ExtendedUbus instance."""
        if self._extended_ubus is None:
            raise RuntimeError("Client not connected. Call connect() first.")
        return getattr(self._extended_ubus, name)


def create_enhanced_extended_ubus_client(
    host: str,
    username: str,
    password: str,
    session=None,
    timeout: int = 30,
    verify_ssl: bool = False,
    cert_file: Optional[str] = None
) -> EnhancedExtendedUbusClient:
    """Create an enhanced ExtendedUbus client with proper SSL handling.

    Args:
        host: OpenWrt device host
        username: Username for authentication
        password: Password for authentication
        session: Existing aiohttp session (optional)
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        cert_file: Path to custom certificate file

    Returns:
        Enhanced ExtendedUbus client wrapper instance
    """
    return EnhancedExtendedUbusClient(
        host=host,
        username=username,
        password=password,
        session=session,
        timeout=timeout,
        verify=verify_ssl,
        cert_file=cert_file
    )