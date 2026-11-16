# Recorded LLM responses

The `llm` and `hybrid` evaluation engines replay JSON files from `llm/` and `hybrid/` here.
They are created only by an explicit live run, which calls the OpenAI API and costs money:

```powershell
backend\venv\Scripts\python -m eval.run --engine all --live --record --write
```

Use `--only <sample-id> ...` to record a few samples first.
