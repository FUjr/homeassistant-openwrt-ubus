"""Client for the OpenWrt ubus API."""

import json
import logging
import time
from typing import Any

import aiohttp

from ..security_utils import redact_sensitive_data
from .const import (
    API_DEF_DEBUG,
    API_DEF_SESSION_ID,
    API_DEF_TIMEOUT,
    API_DEF_VERIFY,
    API_ERROR,
    API_MESSAGE,
    API_SESSION_METHOD_LOGIN,
    API_PARAM_PASSWORD,
    API_PARAM_USERNAME,
    API_RESULT,
    API_RPC_CALL,
    API_RPC_VERSION,
    API_SUBSYS_SESSION,
    API_UBUS_RPC_SESSION,
    HTTP_STATUS_OK,
    UBUS_ERROR_SUCCESS,
    API_UBUS_RPC_SESSION_EXPIRES, _get_error_message, API_SESSION_METHOD_DESTROY, API_SESSION_METHOD_LIST,
)

_LOGGER = logging.getLogger(__name__)


class PreparedCall:
    def __init__(
            self,
            rpc_method: str,
            subsystem: str | None = None,
            method: str | None = None,
            params: dict | None = None,
            rpc_id: str | None = None,
    ):
        self.rpc_method = rpc_method
        self.subsystem = subsystem
        self.method = method
        self.params = params
        self.id = rpc_id


class RPCError(RuntimeError):
    """Custom exception for RPC errors."""
    pass


class Ubus:
    """Interacts with the OpenWrt ubus API."""

    def __init__(
        self,
        host,
        username,
        password,
        session=None,
        timeout=API_DEF_TIMEOUT,
        verify=API_DEF_VERIFY,
        cert_file=None,
    ):
        """Init OpenWrt ubus API."""
        self.host = host
        self.username = username
        self.password = password
        self.session = session  # Session will be provided externally
        self.timeout = timeout
        self.verify = verify
        self.cert_file = cert_file

        self.debug_api = API_DEF_DEBUG
        self.session_id: str | None = None
        self.session_expire = 0
        self._session_created_internally = False

    def set_session(self, session):
        """Set the aiohttp session to use."""
        self.session = session

    async def logout(self):
        """Clear the current session ID."""
        await self._api_call(
            API_RPC_CALL,
            API_SUBSYS_SESSION,
            API_SESSION_METHOD_DESTROY,
        )
        self.session_id = None
        self.session_expire = 0

    def _ensure_session(self):
        """Ensure we have a session, create one if needed."""
        if self.session is None:
            self.session = aiohttp.ClientSession()
            self._session_created_internally = True

    async def _ensure_session_is_valid(self):
        """Ensure session is still valid"""
        if self.session_expire <= (time.time() - 15):
            await self.connect()

    async def api_call(
            self,
            rpc_method: str,
            subsystem: str = None,
            method: str = None,
            params: dict = None,
    ):
        """Build API call data."""
        if self.debug_api:
            # Redact sensitive information from params before logging
            safe_params = redact_sensitive_data(params) if params else {}
            _LOGGER.debug(
                'api build: rpc_method="%s" subsystem="%s" method="%s" params="%s"',
                rpc_method,
                subsystem,
                method,
                safe_params,
            )

    async def batch_call(self, rpcs: list[PreparedCall]) -> list[tuple[str, dict | list | None | Exception]] | None:
        """Execute multiple API calls in a single batch request."""
        await self._ensure_session_is_valid()
        return await self._batch_call(rpcs)

    async def _batch_call(self, rpcs: list[PreparedCall]) -> list[tuple[str, dict | list | None | Exception]] | None:
        self._ensure_session()

        if rpcs[0] and rpcs[0].subsystem != API_SUBSYS_SESSION:
            rpcs.append(
                PreparedCall(  # Session list call for getting the session expiration
                    rpc_method=API_RPC_CALL,
                    subsystem=API_SUBSYS_SESSION,
                    method=API_SESSION_METHOD_LIST,
                    rpc_id="refresh_expiration",
                )
            )

        rpc_calls = []
        for rpc in rpcs:
            params: list[Any] = [self.session_id or API_DEF_SESSION_ID, rpc.subsystem]
            if rpc.rpc_method == API_RPC_CALL:
                if rpc.method:
                    params.append(rpc.method)

                if rpc.params:
                    params.append(rpc.params)
                else:
                    params.append({})
            rpc_call = {
                "jsonrpc": API_RPC_VERSION,
                "method": rpc.rpc_method,
                "params": params,
            }
            if rpc.id is not None:
                rpc_call["id"] = rpc.id
            rpc_calls.append(rpc_call)

        response = await self.session.post(
            self.host, data=json.dumps(rpc_calls), timeout=self.timeout, verify_ssl=self.verify
        )

        if response.status != HTTP_STATUS_OK:
            return None

        responses = await response.json()

        if self.debug_api:
            # Redact sensitive information from response before logging
            safe_response = redact_sensitive_data(json_response)
            _LOGGER.debug(
                'batch call: status="%s" response="%s"',
                response.status,
                safe_response,
            )

        # For batch calls, the response is typically an array of responses
        if isinstance(json_response, list):
            # Check first result for permission error to handle batch-level permissions
            if json_response and len(json_response) > 0:
                first_result = json_response[0]
                if "error" in first_result:
                    error_msg = first_result["error"].get("message", "")
                    if "Access denied" in error_msg:
                        raise PermissionError(error_msg)
            return json_response
        
        # Handle single response format (fallback)
        if API_ERROR in json_response:
            error_message = json_response[API_ERROR].get(API_MESSAGE, "Unknown error")
            error_code = json_response[API_ERROR].get("code", -1)
            
            # Special handling for permission errors
            if error_code == -32002 or "Access denied" in error_message:
                _LOGGER.warning(
                    "Permission denied when calling %s.%s: %s (code: %d)",
                    subsystem,
                    method,
                    error_message,
                    error_code
                )
                raise PermissionError(
                    f"Permission denied for {subsystem}.{method}: {error_message} (code: {error_code})"
                )
                
            # General error handling
            _LOGGER.error(
                "API call failed for %s.%s: %s (code: %d)",
                subsystem,
                method,
                error_message,
                error_code
            )
            raise ConnectionError(
                f"API call failed for {subsystem}.{method}: {error_message} (code: {error_code})"
            )

        # For batch calls, the response is an array of responses
        if isinstance(responses, list):
            results: list[tuple[str, dict | list | None | Exception]] = []
            for i, response in enumerate(responses):
                result_id = response.get("id", "")

                def _append_result(_result: dict | list | None | Exception):
                    results.append((result_id, _result))

                if API_ERROR in response:
                    subsystem = rpcs[i].subsystem
                    method = rpcs[i].method
                    error_message = response[API_ERROR].get(API_MESSAGE, "Unknown error")
                    error_code = response[API_ERROR].get("code", -1)

                    # Special handling for permission errors
                    if error_code == -32002 or "Access denied" in error_message:
                        _LOGGER.warning(
                            "Permission denied when calling %s.%s: %s (code: %d)",
                            subsystem,
                            method,
                            error_message,
                            error_code
                        )
                        _append_result(
                            PermissionError(
                                f"Permission denied for {subsystem}.{method}: {error_message} (code: {error_code})"
                            )
                        )
                    else:
                        # General error handling
                        _LOGGER.error(
                            "API call failed for %s.%s: %s (code: %d)",
                            subsystem,
                            method,
                            error_message,
                            error_code
                        )
                        _append_result(
                            ConnectionError(
                                f"API call failed for {subsystem}.{method}: {error_message} (code: {error_code})"
                            )
                        )
                else:
                    result = response[API_RESULT]
                    if rpcs[i].rpc_method == API_RPC_CALL:
                        if isinstance(result, list):
                            error_code = result[0]
                            error_msg = _get_error_message(error_code)
                            if len(result) == 2:
                                if error_code == UBUS_ERROR_SUCCESS:
                                    # Success - return the data
                                    _append_result(result[1])
                                else:
                                    # Error code - log with descriptive message and return None
                                    _append_result(
                                        RPCError(
                                            f"API call failed with error code {error_code} ({error_msg}): {result[1]}"
                                        )
                                    )
                            elif len(result) == 1:
                                if error_code == UBUS_ERROR_SUCCESS:
                                    # No data returned but success
                                    _append_result(None)
                                else:
                                    _append_result(
                                        RPCError(
                                            f"API call failed with error code {error_code} ({error_msg}): No error message"
                                        )
                                    )
                            else:
                                _append_result(ConnectionError(f"Unexpected API call result format: {result}"))
                        else:
                            _append_result(ConnectionError(f"Unexpected API call result format: {result}"))
                    else:
                        _append_result(result)
            if results[-1][0] == "refresh_expiration":
                session_response = results.pop()[1]
                if isinstance(session_response, Exception):
                    try:
                        raise session_response
                    except (RPCError, PermissionError) as e:
                        _LOGGER.warning("Failed to retrieve session expiration: %s", e)
                elif isinstance(session_response, list):
                    raise ConnectionError(f"Unexpected session API response format: {session_response}")
                elif isinstance(session_response, dict):
                    self.session_expire = time.time() + session_response.get("expires", 0)

            return results
        else:
            raise ConnectionError(f"Unexpected API response format: {responses}")

    async def _api_call(
            self,
            rpc_method: str,
            subsystem: str | None = None,
            method: str | None = None,
            params: dict | None = None,
    ) -> dict | list | None:
        if self.debug_api:
            # Redact sensitive information from params before logging
            safe_params = redact_sensitive_data(params) if params else {}
            _LOGGER.debug(
                'api call: rpc_method="%s" subsystem="%s" method="%s" params="%s"',
                rpc_method,
                subsystem,
                method,
                safe_params,
            )

        _params = [self.session_id, subsystem]
        if rpc_method == API_RPC_CALL:
            if method:
                _params.append(method)

            if params:
                _params.append(params)
            else:
                _params.append({})

        data = json.dumps(
            {
                "jsonrpc": API_RPC_VERSION,
                "id": self.rpc_id,
                "method": rpc_method,
                "params": _params,
            }
        )
        if self.debug_api:
            # Redact sensitive information from debug data
            try:
                parsed_data = json.loads(data)
                safe_data = redact_sensitive_data(parsed_data)
                _LOGGER.debug('api call: data="%s"', json.dumps(safe_data))
            except (json.JSONDecodeError, Exception):
                # If parsing fails, log a generic message without the actual data
                _LOGGER.debug('api call: data="[JSON_DATA_REDACTED]"')

        self.rpc_id += 1
        try:
            # Make the request using the session
            # SSL verification is handled at the session level
            response = await self.session.post(
                self.host, data=data, timeout=self.timeout,
                allow_redirects=False  # Disable automatic redirects to catch HTTP->HTTPS redirects
            )
        except aiohttp.ClientError as req_exc:
            _LOGGER.error("api_call exception: %s", req_exc)
            # Handle SSL certificate errors specifically
            if "SSL" in str(req_exc) or "certificate" in str(req_exc).lower():
                _LOGGER.error("SSL Certificate Error: This is usually caused by using HTTPS with a self-signed certificate.")
                _LOGGER.error("Try using HTTP instead of HTTPS, or disable SSL verification if using self-signed certificates.")
                _LOGGER.error("Current configuration: host=%s, verify_ssl=%s", self.host, self.verify)
                _LOGGER.error("This suggests the device is forcing HTTPS redirection even when HTTP is requested.")
            return None

        if response.status != HTTP_STATUS_OK:
            return None

        json_response = await response.json()

        if self.debug_api:
            # Redact sensitive information from response before logging
            safe_response = redact_sensitive_data(json_response)
            _LOGGER.debug(
                'api call: status="%s" response="%s"',
                response.status,
                safe_response,
            )

        return response

    def api_debugging(self, debug_api):
        """Enable/Disable API calls debugging."""
        self.debug_api = debug_api
        return self.debug_api

    def https_verify(self, verify):
        """Enable/Disable HTTPS verification."""
        self.verify = verify
        return self.verify

    async def connect(self):
        """Connect to OpenWrt ubus API."""
        self.session_expire = 0

        _LOGGER.debug("Starting ubus connection to host: %s", self.host)
        _LOGGER.debug("Authenticating with username: %s", self.username)

        login = await self.api_call(
            API_RPC_CALL,
            API_SUBSYS_SESSION,
            API_SESSION_METHOD_LOGIN,
            {
                API_PARAM_USERNAME: self.username,
                API_PARAM_PASSWORD: self.password,
            },
        )

        _LOGGER.debug("Login response received: %s", "REDACTED" if login else "None")

        if login and API_UBUS_RPC_SESSION in login:
            self.session_id = login[API_UBUS_RPC_SESSION]
            _LOGGER.debug("Authentication successful, received session_id: %s",
                         "VALID_SESSION" if self.session_id else "INVALID_SESSION")
        else:
            self.session_id = None
            _LOGGER.error("Authentication failed - login response: %s",
                         "Empty response" if not login else f"Missing {API_UBUS_RPC_SESSION} key")
            if login:
                _LOGGER.error("Login response keys: %s", list(login.keys()) if isinstance(login, dict) else "Not a dict")

        return self.session_id

    async def close(self):
        """Close the aiohttp session if we created it internally."""
        if self.session and not self.session.closed and self._session_created_internally:
            await self.session.close()
            self.session = None
            self._session_created_internally = False
