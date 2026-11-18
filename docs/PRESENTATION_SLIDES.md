# Technical presentation

The submission deck has five slides:

- [PRESENTATION.pptx](PRESENTATION.pptx), editable;
- [PRESENTATION.pdf](PRESENTATION.pdf), for viewing without PowerPoint.

Both are generated from [presentation/build.py](presentation/build.py):

```
python docs/presentation/build.py      # rebuilds both files; fails if either has more than 5 slides
```

| Slide | Content |
|---|---|
| 1 | The problem and what ULPF does about it |
| 2 | Architecture |
| 3 | The five differentiators, each demonstrated on the live pipeline |
| 4 | Measured performance and resilience |
| 5 | Problem-statement coverage |

Every number on the slides comes from [architecture_document/figures.json](architecture_document/figures.json), and each figure there names the result file under `benchmarks/results/` it was measured in. To update a number, re-run the benchmark, edit `figures.json`, and rebuild both this deck and the architecture document (`python docs/architecture_document/build.py`).
