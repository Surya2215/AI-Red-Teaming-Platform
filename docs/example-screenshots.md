# Example Screenshots and Mockups

## Targets

```text
+--------------------------------------------------------------+
| Targets                                                      |
| Search targets [ Internal ]                                  |
|                                                              |
| Saved targets                 Create or edit target           |
| Internal HR Chatbot           Target name [ Internal HR... ]  |
| { JSON template }             URL [ mock://internal... ]      |
|                               Method [ POST ]                |
|                               [ Validate and save target ]    |
+--------------------------------------------------------------+
```

## Scan

```text
+--------------------------------------------------------------+
| Scan                                                         |
| Scan name [ LLM01 Scan 2026-05-15 10:30 ]                    |
| Target [ Internal HR Chatbot ]                               |
| [x] Prompt Injection   [x] Crescendo Attack                  |
| Max turns [6] Timeout [30] Concurrency [2] Retry [2]          |
| [ Start scan ]                                               |
| Progress: ####################### 100%                       |
| Current stage: detectors_completed                           |
+--------------------------------------------------------------+
```

## Results

```text
+--------------------------------------------------------------------------------+
| Scan Name        Target              Scenario           Severity Confidence     |
| LLM01 Scan       Internal HR Chatbot Prompt Injection   HIGH     0.91           |
| LLM01 Scan       Internal HR Chatbot Crescendo Attack   HIGH     0.84           |
+--------------------------------------------------------------------------------+
```

