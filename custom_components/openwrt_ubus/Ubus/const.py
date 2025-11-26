"""OpenWrt ubus API Basic Constants."""

# Basic ubus API constants
API_DEF_DEBUG = True
API_DEF_SESSION_ID = "00000000000000000000000000000000"
API_DEF_TIMEOUT = 15
API_DEF_VERIFY = False

API_ERROR = "error"
API_MESSAGE = "message"
API_RESULT = "result"
API_RPC_CALL = "call"
API_RPC_ID = 1
API_RPC_LIST = "list"
API_RPC_VERSION = "2.0"
API_UBUS_RPC_SESSION = "ubus_rpc_session"
API_UBUS_RPC_SESSION_EXPIRES = "expires"

# Basic parameters
API_PARAM_PASSWORD = "password"
API_PARAM_USERNAME = "username"

# Basic subsystems
API_SUBSYS_SESSION = "session"

# Basic methods
API_SESSION_METHOD_LOGIN = "login"
API_SESSION_METHOD_DESTROY = "destroy"
API_SESSION_METHOD_LIST = "list"

# Common ubus error codes
UBUS_ERROR_SUCCESS = 0
UBUS_ERROR_INVALID_COMMAND = 1
UBUS_ERROR_INVALID_ARGUMENT = 2
UBUS_ERROR_METHOD_NOT_FOUND = 3
UBUS_ERROR_NOT_FOUND = 4
UBUS_ERROR_NO_DATA = 5
UBUS_ERROR_PERMISSION_DENIED = 6
UBUS_ERROR_TIMEOUT = 7
UBUS_ERROR_NOT_SUPPORTED = 8
UBUS_ERROR_UNKNOWN_ERROR = 9

HTTP_STATUS_OK = 200


def _get_error_message(error_code):
    """Get descriptive error message for ubus error codes."""
    error_messages = {
        UBUS_ERROR_SUCCESS: "Success",
        UBUS_ERROR_PERMISSION_DENIED: "Permission Denied",
        UBUS_ERROR_NOT_FOUND: "Not Found",
        UBUS_ERROR_NO_DATA: "No Data",
    }
    return error_messages.get(error_code, f"Unknown Error ({error_code})")
