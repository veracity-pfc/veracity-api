from app.schemas.url_analysis import UrlAnalysisIn, UrlAnalysisOut
from app.domain.enums import RiskLabel

def test_url_analysis_in():
    obj = UrlAnalysisIn(url="https://nubank.com.br/")
    assert obj.url == "https://nubank.com.br/"

def test_url_analysis_out():
    out = UrlAnalysisOut(
        id="abc",
        analysis_id="an1",
        url="https://nubank.com.br/",
        label=RiskLabel.safe,
        explanation="URL considerada segura",
        recommendations=["Manter boas práticas de navegação"]
    )
    assert out.label == RiskLabel.safe
    assert out.explanation
    assert isinstance(out.recommendations, list) and len(out.recommendations) >= 1
