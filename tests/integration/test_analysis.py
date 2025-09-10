import pytest
from httpx import AsyncClient
from app.main import app

@pytest.mark.asyncio
async def test_invalid_url():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/analysis/link", json={"url": "abc"})
        assert response.status_code == 400

@pytest.mark.asyncio
async def test_valid_analysis():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/analysis/link", json={"url": "https://teams.microsoft.com/"})
        assert response.status_code == 200
        assert "classification" in response.json()
