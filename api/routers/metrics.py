from fastapi import APIRouter

from api.services.data_loader import load_ablation, load_atc, load_validation_metrics

router = APIRouter()


@router.get("/validation")
def get_validation():
    df = load_validation_metrics()
    return df.to_dict(orient="records")[0] if not df.empty else {}


@router.get("/ablation")
def get_ablation():
    df = load_ablation()
    return df.to_dict(orient="records")


@router.get("/atc")
def get_atc():
    df = load_atc()
    return df.to_dict(orient="records")
