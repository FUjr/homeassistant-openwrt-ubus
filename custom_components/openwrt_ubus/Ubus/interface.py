"""Client for the OpenWrt ubus API."""

import json
import logging
import time
from typing import Any

import aiohttp

from .const import (
    API_DEF_DEBUG,
    API_DEF_SESSION_ID,
    API_DEF_TIMEOUT,
    API_DEF_VERIFY,
    API_ERROR,
    API_MESSAGE,
    API_METHOD_LOGIN,
    API_PARAM_PASSWORD,
    API_PARAM_USERNAME,
    API_RESULT,
    API_RPC_CALL,
    API_RPC_ID,
    API_RPC_VERSION,
    API_SUBSYS_SESSION,
    API_UBUS_RPC_SESSION,
    HTTP_STATUS_OK,
    UBUS_ERROR_SUCCESS,
    UBUS_ERROR_PERMISSION_DENIED,
    UBUS_ERROR_NOT_FOUND,
    UBUS_ERROR_NO_DATA, API_UBUS_RPC_SESSION_EXPIRES,
)

_LOGGER = logging.getLogger(__name__)


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
    ):
        """Init OpenWrt ubus API."""
        self.host = host
        self.username = username
        self.password = password
        self.session = session  # Session will be provided externally
        self.timeout = timeout
        self.verify = verify

        self.debug_api = API_DEF_DEBUG
        self.rpc_id = API_RPC_ID
        self.session_id = None
        self.session_expire = 0
        self._session_created_internally = False

    def set_session(self, session):
        """Set the aiohttp session to use."""
        self.session = session

    def logout(self):
        """Clear the current session ID."""
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

    def build_api(
            self,
            rpc_method: str,
            subsystem: str = None,
            method: str = None,
            params: dict = None,
    ):
        """Build API call data."""
        if self.debug_api:
            _LOGGER.debug(
                'api build: rpc_method="%s" subsystem="%s" method="%s" params="%s"',
                rpc_method,
                subsystem,
                method,
                params,
            )

        _params: list[Any] = [subsystem]
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
        self.rpc_id += 1
        return data

    async def batch_call(self, rpcs: list[dict]):
        """Execute multiple API calls in a single batch request."""
        self._ensure_session()
        await self._ensure_session_is_valid()

        for rpc in rpcs:
            rpc["params"] = [self.session_id] + rpc.get("params", [])

        try:
            response = await self.session.post(
                self.host, data=json.dumps(rpcs), timeout=self.timeout, verify_ssl=self.verify
            )
        except aiohttp.ClientError as req_exc:
            _LOGGER.error("batch_call exception: %s", req_exc)
            return None

        if response.status != HTTP_STATUS_OK:
            return None

        json_response = await response.json()

        if self.debug_api:
            _LOGGER.debug(
                'batch call: status="%s" response="%s"',
                response.status,
                json_response,
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
        return [json_response]

    async def api_call(
            self,
            rpc_method: str,
            subsystem: str | None = None,
            method: str | None = None,
            params: dict | None = None,
    ):
        """Perform API call."""
        await self._ensure_session_is_valid()
        return await self._api_call(rpc_method, subsystem, method, params)

    async def _api_call(
            self,
            rpc_method: str,
            subsystem: str | None = None,
            method: str | None = None,
            params: dict | None = None,
    ):
        self._ensure_session()
        if self.debug_api:
            _LOGGER.debug(
                'api call: rpc_method="%s" subsystem="%s" method="%s" params="%s"',
                rpc_method,
                subsystem,
                method,
                params,
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
            _LOGGER.debug('api call: data="%s"', data)

        self.rpc_id += 1
        try:
            response = await self.session.post(
                self.host, data=data, timeout=self.timeout, verify_ssl=self.verify
            )
        except aiohttp.ClientError as req_exc:
            _LOGGER.error("api_call exception: %s", req_exc)
            return None

        if response.status != HTTP_STATUS_OK:
            return None

        json_response = await response.json()

        if self.debug_api:
            _LOGGER.debug(
                'api call: status="%s" response="%s"',
                response.status,
                json_response,
            )

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

        if rpc_method == API_RPC_CALL:
            try:
                result = json_response[API_RESULT]
                if isinstance(result, list) and len(result) > 1:
                    # Check if first element is an error code
                    error_code = result[0]
                    if error_code == UBUS_ERROR_SUCCESS:
                        # Success - return the data
                        return result[1]
                    else:
                        # Error code - log with descriptive message and return None
                        error_msg = self._get_error_message(error_code)
                        _LOGGER.debug("API call failed with error code %s (%s): %s",
                                      error_code, error_msg, result[1] if len(result) > 1 else "No error message")
                        return None
                elif isinstance(result, list) and len(result) == 1:
                    # Single element result - might be an error code
                    error_code = result[0]
                    error_msg = self._get_error_message(error_code)
                    _LOGGER.debug("API call failed with error code %s (%s) - no error message", error_code, error_msg)
                    return None
                else:
                    _LOGGER.debug("Unexpected result format: %s", result)
                    return None
            except (IndexError, KeyError) as exc:
                _LOGGER.debug("Error parsing API result: %s", exc)
                return None
        else:
            return json_response[API_RESULT]

    def _get_error_message(self, error_code):
        """Get descriptive error message for ubus error codes."""
        error_messages = {
            UBUS_ERROR_SUCCESS: "Success",
            UBUS_ERROR_PERMISSION_DENIED: "Permission Denied",
            UBUS_ERROR_NOT_FOUND: "Not Found",
            UBUS_ERROR_NO_DATA: "No Data",
        }
        return error_messages.get(error_code, f"Unknown Error ({error_code})")

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
        self.rpc_id = 1
        self.session_id = API_DEF_SESSION_ID
        self.session_expire = 0

        login = await self._api_call(
            API_RPC_CALL,
            API_SUBSYS_SESSION,
            API_METHOD_LOGIN,
            {
                API_PARAM_USERNAME: self.username,
                API_PARAM_PASSWORD: self.password,
            },
        )
        if login and API_UBUS_RPC_SESSION in login:
            self.session_id = login[API_UBUS_RPC_SESSION]
            self.session_expire = time.time() + int(login[API_UBUS_RPC_SESSION_EXPIRES])
        else:
            self.session_id = None

        return self.session_id

    async def close(self):
        """Close the aiohttp session if we created it internally."""
        if self.session and not self.session.closed and self._session_created_internally:
            await self.session.close()
            self.session = None
            self._session_created_internally = False
