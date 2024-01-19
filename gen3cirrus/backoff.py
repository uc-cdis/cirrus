"""
Module to consolidate exponential backoff settings and functions
"""
from cdislogging import get_logger
from googleapiclient.errors import HttpError as GoogleHttpError
import json
import sys

from gen3cirrus.errors import CirrusError

logger = get_logger(__name__)


def _print_func_name(function):
    return "{}.{}".format(function.__module__, function.__name__)


def _print_kwargs(kwargs):
    return ", ".join("{}={}".format(k, repr(v)) for k, v in list(kwargs.items()))


def log_backoff_retry(details):
    args_str = ", ".join(map(str, details["args"]))
    kwargs_str = (
        (", " + _print_kwargs(details["kwargs"])) if details.get("kwargs") else ""
    )
    func_call_log = "{}({}{})".format(
        _print_func_name(details["target"]), args_str, kwargs_str
    )
    logger.warning(
        "backoff: call {func_call} delay {wait:0.1f} seconds after {tries} tries".format(
            func_call=func_call_log, **details
        )
    )


def log_backoff_giveup(details):
    args_str = ", ".join(map(str, details["args"]))
    kwargs_str = (
        (", " + _print_kwargs(details["kwargs"])) if details.get("kwargs") else ""
    )
    func_call_log = "{}({}{})".format(
        _print_func_name(details["target"]), args_str, kwargs_str
    )
    logger.error(
        "backoff: gave up call {func_call} after {tries} tries; exception: {exc}".format(
            func_call=func_call_log, exc=sys.exc_info(), **details
        )
    )


def get_reason(http_error):
    """
    temporary solution to work around googleapiclient bug that doesn't
    parse reason from server response
    """
    reason = http_error.resp.reason
    try:
        data = json.loads(http_error.content.decode("utf-8"))
        if isinstance(data, dict):
            reason = data["error"].get("reason")
            if "errors" in data["error"] and len(data["error"]["errors"]) > 0:
                reason = data["error"]["errors"][0]["reason"]
    except (ValueError, KeyError, TypeError):
        pass
    if reason is None:
        reason = ""
    return reason


def exception_do_not_retry(e):
    """
    True if we should not retry.
    - We should not retry for errors that we raise (CirrusErrors)
    - We should not retry for Google errors that are not temporary
      and not recoverable by retry
    """
    if isinstance(e, GoogleHttpError):
        if e.resp.status == 403:
            # Then we should return True unless it's a rate limit error.
            # Note: There is overlap in the reason codes for these APIs
            # which is not ideal. e.g. userRateLimitExceeded is in both
            # resource manager API and directory API.
            # Fortunately both cases warrant retrying.
            # Valid rate limit reasons from CLOUD RESOURCE MANAGER API:
            # cloud.google.com/resource-manager/docs/core_errors#FORBIDDEN
            # Many limit errors listed; only a few warrant retry.
            resource_rlreasons = [
                "concurrentLimitExceeded",
                "limitExceeded",
                "rateLimitExceeded",
                "userRateLimitExceeded",
            ]
            # Valid rate limit reasons from DIRECTORY API:
            # developers.google.com/admin-sdk/directory/v1/limits
            directory_rlreasons = ["userRateLimitExceeded", "quotaExceeded"]
            # Valid rate limit reasons from IAM API:
            # IAM API doesn't seem to return rate-limit 403s.

            reason = get_reason(e) or e.resp.reason
            logger.info("Got 403 from google with reason {}".format(reason))
            return (
                reason not in resource_rlreasons and reason not in directory_rlreasons
            )
        return False

    return isinstance(e, CirrusError)


# Default settings to control usage of backoff library.
BACKOFF_SETTINGS = {
    "on_backoff": log_backoff_retry,
    "on_giveup": log_backoff_giveup,
    "max_tries": 5,
    "giveup": exception_do_not_retry,
}
