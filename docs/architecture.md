# Architecture

```mermaid
flowchart LR
    UI["Streamlit UI"] --> API["FastAPI API"]
    UI --> ORCH["Scan Orchestrator"]
    API --> ORCH
    ORCH --> AE["Attack Engine"]
    ORCH --> DE["Detector Engine"]
    AE --> SL["Scenario Loader"]
    DE --> DL["Detector Loader"]
    AE --> TE["Target Executor"]
    AE --> JA["Judge Agent"]
    JA --> AOAI["Azure OpenAI"]
    DE --> AOAI
    TE --> TARGET["Target App"]
    ORCH --> DB["SQLAlchemy Database"]
    ORCH --> REPORTS["JSON/PDF Reports"]
    ORCH --> LOGS["Structured JSON Logs"]
```

The architecture is intentionally modular. Scenario and detector plugins are loaded from the filesystem, the orchestrator is independent from the UI, and persistence uses SQLAlchemy models that can move from SQLite to PostgreSQL by changing `DATABASE_URL`.

Future distributed execution can attach a queue boundary between `ScanOrchestrator` and `AttackEngine`. Celery, Kafka, or Kubernetes Jobs can consume scan requests without changing detector or scenario plugin contracts.

