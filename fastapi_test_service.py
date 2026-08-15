from fastapi import FastAPI


app = FastAPI(title="Port Scanner Test Service")


@app.get("/")
def root() -> dict[str, str]:
    return {"status": "ok", "service": "port-scanner-test"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"healthy": "true"}
