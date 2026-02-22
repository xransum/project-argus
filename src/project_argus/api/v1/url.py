"""URL validation and analysis API endpoints"""

import logging
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Query
from pydantic import ValidationError

from ...utils.validators import URLValidator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/url", tags=["url"])


@router.get("/validate")
async def validate_url_endpoint(
    url: str = Query(..., description="URL to validate")
) -> Dict[str, Any]:
    """
    Validate a URL format.

    Args:
        url: URL to validate

    Returns:
        Validation result with sanitized URL

    Raises:
        HTTPException: If URL is invalid
    """
    try:
        validator = URLValidator(url=url)
        return {"valid": True, "url": validator.url, "message": "URL is valid"}
    except ValidationError as e:
        error_msg = e.errors()[0]["msg"]
        logger.warning(f"Invalid URL validation: {url} - {error_msg}")
        raise HTTPException(status_code=400, detail=error_msg)
    except Exception as e:
        logger.error(f"Unexpected error validating URL: {url} - {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/status")
async def get_url_status(
    url: str = Query(..., description="URL to check status")
) -> Dict[str, Any]:
    """
    Get HTTP status of a URL.

    Args:
        url: URL to check

    Returns:
        URL status information
    """
    try:
        validator = URLValidator(url=url)
        sanitized_url = validator.url

        # Add your URL status checking logic here
        return {
            "url": sanitized_url,
            "valid": True,
            # Add status code, response time, etc.
        }
    except ValidationError as e:
        error_msg = e.errors()[0]["msg"]
        raise HTTPException(status_code=400, detail=error_msg)


@router.get("/headers")
async def get_url_headers(
    url: str = Query(..., description="URL to get headers from")
) -> Dict[str, Any]:
    """
    Get HTTP headers from a URL.

    Args:
        url: URL to get headers from

    Returns:
        URL headers information
    """
    try:
        validator = URLValidator(url=url)
        sanitized_url = validator.url

        # Add your URL headers fetching logic here
        return {
            "url": sanitized_url,
            "valid": True,
            # Add headers data
        }
    except ValidationError as e:
        error_msg = e.errors()[0]["msg"]
        raise HTTPException(status_code=400, detail=error_msg)
