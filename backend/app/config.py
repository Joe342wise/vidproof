from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    storage_dir: Path = Path("storage")
    fabric_adapter_url: str = "http://localhost:8081"
    tsa_url: str = "http://localhost:2560"
    tsa_ca_cert: Path = Path("infra/tsa/ca.crt")
    tsa_cert: Path = Path("infra/tsa/tsa.crt")

    @property
    def evidence_dir(self) -> Path:
        return self.storage_dir / "evidence"

    @property
    def metadata_dir(self) -> Path:
        return self.storage_dir / "metadata"

    @property
    def keys_dir(self) -> Path:
        return self.storage_dir / "keys"

    @property
    def cameras_dir(self) -> Path:
        return self.metadata_dir / "cameras"

    @property
    def evidence_meta_dir(self) -> Path:
        return self.metadata_dir / "evidence"

    @property
    def results_dir(self) -> Path:
        return self.metadata_dir / "results"

    @property
    def tsa_dir(self) -> Path:
        return self.storage_dir / "tsa"

    model_config = {"env_prefix": "VIDPROOF_"}


settings = Settings()
