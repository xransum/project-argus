"""URL API endpoints for Project Argus"""

from fastapi import APIRouter, Depends, HTTPException
from typing_extensions import Annotated

from ...models.url_models import URLHeadersResponse, URLStatusResponse
from ...services.url_service import URLService
from ...utils.validators import validate_url

router = APIRouter()
service = URLService()


@router.get("/status", response_model=URLStatusResponse)
async def check_url_status(url: Annotated[str, Depends(validate_url)]) -> URLStatusResponse:
    """Check the status of a URL"""
    try:
        return await service.check_status(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/headers", response_model=URLHeadersResponse)
async def get_url_headers(url: Annotated[str, Depends(validate_url)]) -> URLHeadersResponse:
    """Fetch the headers of a URL"""
    try:
        return await service.get_headers(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
