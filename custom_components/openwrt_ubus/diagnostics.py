"""Diagnostic tools for OpenWrt ubus connection troubleshooting."""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, Any, Optional

from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    CONF_HOST,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_USE_HTTPS,
    CONF_VERIFY_SSL,
    DEFAULT_USE_HTTPS,
    DEFAULT_VERIFY_SSL,
)
from .ubus_client import create_enhanced_ubus_client

_LOGGER = logging.getLogger(__name__)


class ConnectionDiagnostics:
    """Diagnostic tools for OpenWrt ubus connections."""

    @staticmethod
    async def test_connection(
        hass,
        host: str,
        username: str,
        password: str,
        use_https: bool = DEFAULT_USE_HTTPS,
        verify_ssl: bool = DEFAULT_VERIFY_SSL,
        cert_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Test connection to OpenWrt device and return diagnostic information.

        Args:
            hass: Home Assistant instance
            host: OpenWrt device host
            username: Username for authentication
            password: Password for authentication
            use_https: Whether to use HTTPS
            verify_ssl: Whether to verify SSL certificates
            cert_path: Path to custom certificate file

        Returns:
            Dictionary containing diagnostic information
        """
        results = {
            "success": False,
            "error": None,
            "error_type": None,
            "details": {},
            "recommendations": []
        }

        try:
            # Build URL
            protocol = "https" if use_https else "http"
            url = f"{protocol}://{host}/ubus"

            _LOGGER.info("Starting diagnostic connection test to %s://%s", protocol, host)

            # Create client
            session = async_get_clientsession(hass)
            client = create_enhanced_ubus_client(
                url,
                username,
                password,
                session=session,
                verify_ssl=verify_ssl,
                cert_file=cert_path
            )

            # Test connection
            _LOGGER.debug("Attempting ubus connection")
            session_id = await client.connect()

            if session_id:
                results["success"] = True
                results["details"]["session_id"] = session_id
                results["details"]["connection_established"] = True
                _LOGGER.info("Diagnostic test successful: session_id = %s", session_id)

                # Test basic ubus functionality
                try:
                    ubus_list = await client.list()
                    results["details"]["ubus_services"] = len(ubus_list) if ubus_list else 0
                    _LOGGER.debug("Found %d ubus services", results["details"]["ubus_services"])
                except Exception as exc:
                    _LOGGER.warning("Could not list ubus services: %s", exc)
                    results["details"]["ubus_services"] = "unknown"

            else:
                results["error"] = "Connection failed - session_id is None"
                results["error_type"] = "authentication_failure"
                results["recommendations"].append("Check username and password")
                results["recommendations"].append("Verify user has ubus access permissions")
                results["recommendations"].append("Check if OpenWrt ubus service is running")

            await client.close()

        except ConnectionRefusedError as exc:
            results["error"] = f"Connection refused: {exc}"
            results["error_type"] = "connection_refused"
            results["recommendations"].append("Check if OpenWrt device is running and accessible")
            results["recommendations"].append("Verify the IP address is correct")
            results["recommendations"].append("Check firewall settings between Home Assistant and OpenWrt")
            _LOGGER.error("Diagnostic test failed: Connection refused")

        except asyncio.TimeoutError as exc:
            results["error"] = f"Connection timeout: {exc}"
            results["error_type"] = "timeout"
            results["recommendations"].append("Check network connectivity")
            results["recommendations"].append("Verify OpenWrt device is not overloaded")
            results["recommendations"].append("Try increasing timeout settings")
            _LOGGER.error("Diagnostic test failed: Connection timeout")

        except PermissionError as exc:
            results["error"] = f"Authentication failed: {exc}"
            results["error_type"] = "authentication_error"
            results["recommendations"].append("Verify username and password are correct")
            results["recommendations"].append("Check if user has sufficient privileges")
            results["recommendations"].append("Try using the root user or an administrator account")
            _LOGGER.error("Diagnostic test failed: Authentication error")

        except Exception as exc:
            results["error"] = f"Unexpected error: {exc}"
            results["error_type"] = "unknown_error"
            results["recommendations"].append("Check Home Assistant logs for more details")
            results["recommendations"].append("Verify OpenWrt device configuration")
            results["recommendations"].append("Try restarting both Home Assistant and OpenWrt device")
            _LOGGER.error("Diagnostic test failed: Unexpected error: %s", exc)

        # Add connection details
        results["details"]["protocol"] = protocol
        results["details"]["host"] = host
        results["details"]["username"] = username
        results["details"]["use_https"] = use_https
        results["details"]["verify_ssl"] = verify_ssl
        results["details"]["cert_path"] = cert_path if cert_path else None

        return results

    @staticmethod
    def generate_recommendations(diagnostic_results: Dict[str, Any]) -> str:
        """Generate human-readable recommendations based on diagnostic results.

        Args:
            diagnostic_results: Results from test_connection

        Returns:
            Human-readable recommendations
        """
        if diagnostic_results["success"]:
            return "✅ Connection successful! OpenWrt ubus is working correctly."

        error_type = diagnostic_results.get("error_type", "unknown")
        recommendations = diagnostic_results.get("recommendations", [])

        output = f"❌ Connection failed ({error_type})\n\n"
        output += "Recommendations:\n"

        for i, rec in enumerate(recommendations, 1):
            output += f"{i}. {rec}\n"

        # Add specific troubleshooting steps based on error type
        if error_type == "authentication_failure":
            output += "\nAdditional steps for authentication issues:\n"
            output += "- Try logging into OpenWrt Web UI with the same credentials\n"
            output += "- Check if the ubus service is running: `ubus list`\n"
            output += "- Restart the ubus service: `/etc/init.d/ubus restart`\n"

        elif error_type == "connection_refused":
            output += "\nAdditional steps for connection issues:\n"
            output += "- Ping the OpenWrt device from Home Assistant host\n"
            output += "- Check if OpenWrt firewall allows connections from Home Assistant\n"
            output += "- Verify OpenWrt device is on the same network as Home Assistant\n"

        elif error_type == "timeout":
            output += "\nAdditional steps for timeout issues:\n"
            output += "- Check network latency between Home Assistant and OpenWrt\n"
            output += "- Monitor OpenWrt device CPU usage\n"
            output += "- Consider using HTTP instead of HTTPS for local networks\n"

        return output

    @staticmethod
    async def quick_test(hass, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Quick connection test using config data.

        Args:
            hass: Home Assistant instance
            config_data: Configuration data

        Returns:
            Diagnostic results
        """
        return await ConnectionDiagnostics.test_connection(
            hass=hass,
            host=config_data.get(CONF_HOST),
            username=config_data.get(CONF_USERNAME),
            password=config_data.get(CONF_PASSWORD),
            use_https=config_data.get(CONF_USE_HTTPS, DEFAULT_USE_HTTPS),
            verify_ssl=config_data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
            cert_path=config_data.get(CONF_CERT_PATH),
        )